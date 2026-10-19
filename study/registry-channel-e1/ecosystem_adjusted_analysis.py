"""E1 analysis -- the ecosystem-coverage confound for the registry-channel effect.

This is the FROZEN analysis script for registry-channel E1
(PREREGISTRATION-registry-channel-e1.md, registered 2026-10-19 before A4's census
was read). It is committed BEFORE A4's `real_package_census.csv` exists, so the
ecosystem adjustment cannot be tuned after seeing the data -- the whole point of a
pre-registration.

E1 adds NO new data collection and NO new compute job: it re-analyses A4's census.
For every eligible advisory in the 32-application frame it derives one OSV
*ecosystem stratum* from A4's already-parsed package column, then asks whether the
registry -> scanner-visibility difference SURVIVES holding ecosystem fixed
(a Mantel-Haenszel-style stratified estimate with a within-stratum label
permutation test), or whether the registry "effect" is substantially an artefact
of OSV indexing some ecosystems better than others (Confound C).

Inputs (read-only, offline): A4's `real_package_census.csv` and the frozen
`registry_classification.json` (repo -> registry/no_registry). No network.

Outputs (per the pre-registration):
  ecosystem_adjusted_summary.json  P1 adjusted difference + permutation p +
                                   usable strata; P2 per-group stratum table +
                                   well-indexed-share test; P3 per-ecosystem
                                   visible-rate; the power-floor verdict.
  ecosystem_census.csv             A4's rows (32-app frame) + the derived stratum.
  ecosystem_adjusted_meta.json     input shas, counts, seed, well-indexed set.

Stdlib only, Python 3.9+. Apache-2.0, made with AI agents working for
MV2 of Munim, Inc. No result here has been reviewed by a human.
"""
import argparse
import csv
import hashlib
import json
import math
import os
import random
import sys
from collections import defaultdict

# ---- Frozen constants (match the A4 collector / the E1 pre-registration) -----
PERM_SEED = 20261017
N_PERM = 10000
# Well-indexed ecosystems (frozen set in the pre-registration, P2).
WELL_INDEXED = ("npm", "PyPI", "Go", "RubyGems", "crates.io", "Packagist")
P1_MIN_POINTS = 25.0          # adjusted effect must be >= +25 pts to "survive"
P1_ALPHA = 0.05
MIN_REPOS_PER_GROUP = 2       # power floor: a stratum needs >=2 repos in EACH group
MIN_USABLE_STRATA = 3         # power floor: >=3 usable strata, else INCONCLUSIVE
MIN_TOTAL_REPOS = 6           # power floor: usable strata hold >=6 distinct repos

# Canonical OSV/GHSA ecosystem names. The raw values are GitHub advisory
# "ecosystem" query tokens (lower-cased by the A4 collector): npm, pip, rubygems,
# maven, nuget, composer, go, rust, erlang, actions, pub, swift.
ECO_CANON = {
    "npm": "npm",
    "pip": "PyPI", "pypi": "PyPI",
    "composer": "Packagist", "packagist": "Packagist",
    "rubygems": "RubyGems", "gem": "RubyGems",
    "rust": "crates.io", "crates.io": "crates.io", "cargo": "crates.io",
    "go": "Go", "golang": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "pub": "Pub", "swift": "Swift",
    "erlang": "Hex", "hex": "Hex",
    "actions": "Actions",
}


def canon_eco(raw):
    """Canonical ecosystem name for a raw GitHub ecosystem token, or 'other'."""
    return ECO_CANON.get((raw or "").strip().lower(), "other")


def parse_named_packages(field):
    """A4's `named_packages` column -> ordered [(eco_lower, name)] in page order."""
    out = []
    for part in (field or "").split(";"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        eco, name = part.split(":", 1)
        eco = eco.strip().lower()
        name = name.strip()
        if name:
            out.append((eco, name))
    return out


def derive_stratum(row):
    """Return (stratum, source) for one A4 census row, per the frozen E1 rule.

    stratum is None iff the advisory is EXCLUDED (product_type == 'other', as
    A3/A4 exclude). 'none' is the software-typed (no named package) stratum.
    For package-typed advisories the stratum is the canonical ecosystem of the
    FIRST named-package coordinate in page order; if the bold-span name parse
    recorded nothing, it falls back to the first (alphabetical) advisory
    ecosystem the page's ecosystem-query links already proved."""
    pt = (row.get("advisory_product_type") or "").strip()
    if pt == "software":
        return "none", "software"
    if pt == "package":
        pkgs = parse_named_packages(row.get("named_packages"))
        if pkgs:
            return canon_eco(pkgs[0][0]), "named_package_first"
        ecos = [e for e in (row.get("advisory_ecosystems") or "").split(";") if e.strip()]
        if ecos:
            return canon_eco(sorted(ecos)[0]), "ecosystem_fallback"
        return "other", "package_no_ecosystem"
    return None, "excluded_other"


def is_visible(row):
    return (row.get("scanner_class") or "").strip() == "scanner_visible"


# --------------------------------------------------------------------------- #
# Loading: keep only the 32-app frame, attach registry/no_registry + stratum.  #
# --------------------------------------------------------------------------- #

def load_classification(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    cls = data.get("classification", data)
    # repo (lower) -> "registry"/"no_registry"
    out = {}
    for repo, meta in cls.items():
        g = meta.get("group") if isinstance(meta, dict) else meta
        if g in ("registry", "no_registry"):
            out[repo.lower()] = g
    return out


def load_rows(census_csv, classification):
    """Read A4's census, keep rows whose repo is in the classification (the 32
    apps), and attach group + stratum. Returns (rows, skipped_not_in_frame)."""
    rows, skipped = [], 0
    with open(census_csv, newline="", encoding="utf-8") as f:
        for raw in csv.DictReader(f):
            repo = (raw.get("repo") or "").strip()
            group = classification.get(repo.lower())
            if group is None:
                skipped += 1           # a library (frame_libs) or anything off-frame
                continue
            stratum, source = derive_stratum(raw)
            rows.append({
                "repo": repo,
                "group": group,
                "ghsa_id": raw.get("ghsa_id", ""),
                "cve_id": raw.get("cve_id", ""),
                "advisory_product_type": raw.get("advisory_product_type", ""),
                "advisory_ecosystems": raw.get("advisory_ecosystems", ""),
                "named_packages": raw.get("named_packages", ""),
                "named_pkg_resolution": raw.get("named_pkg_resolution", ""),
                "real_package": raw.get("real_package", ""),
                "scanner_class": raw.get("scanner_class", ""),
                "visible": is_visible(raw),
                "ecosystem_stratum": "excluded_other" if stratum is None else stratum,
                "stratum_source": source,
                "included": stratum is not None,
            })
    return rows, skipped


# --------------------------------------------------------------------------- #
# Statistics.                                                                  #
# --------------------------------------------------------------------------- #

def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(centre - half, 4), round(centre + half, 4)]


def _mean(xs):
    return sum(xs) / len(xs) if xs else None


def build_stratum_table(included_rows):
    """stratum -> group -> {adv, vis, repos(set)}; only included rows."""
    table = defaultdict(lambda: {
        "registry": {"adv": 0, "vis": 0, "repos": set()},
        "no_registry": {"adv": 0, "vis": 0, "repos": set()},
    })
    for r in included_rows:
        cell = table[r["ecosystem_stratum"]][r["group"]]
        cell["adv"] += 1
        cell["vis"] += 1 if r["visible"] else 0
        cell["repos"].add(r["repo"])
    return table


def usable_strata(table):
    """Strata with >= MIN_REPOS_PER_GROUP repositories in EACH group."""
    out = []
    for stratum, groups in table.items():
        if (len(groups["registry"]["repos"]) >= MIN_REPOS_PER_GROUP
                and len(groups["no_registry"]["repos"]) >= MIN_REPOS_PER_GROUP):
            out.append(stratum)
    return sorted(out)


def _mh_rd(per_stratum):
    """Mantel-Haenszel-style common risk difference (fraction) from a list of
    (n1, k1, n0, k0) advisory counts. Weight w = n1*n0/(n1+n0)."""
    num = den = 0.0
    for n1, k1, n0, k0 in per_stratum:
        if n1 <= 0 or n0 <= 0:
            continue
        w = (n1 * n0) / (n1 + n0)
        d = (k1 / n1) - (k0 / n0)
        num += w * d
        den += w
    return (num / den) if den > 0 else 0.0


def compute_p1(included_rows, n_perm=N_PERM, seed=PERM_SEED):
    """P1: does the registry->visibility difference survive ecosystem adjustment?

    Returns a dict with the MH adjusted difference (points), the within-stratum
    label-permutation p (two- and one-sided), the usable-stratum detail, and the
    power-floor verdict."""
    table = build_stratum_table(included_rows)
    usable = usable_strata(table)

    # advisory visibilities grouped by stratum then repo (for permutation).
    by_sr = defaultdict(lambda: defaultdict(list))   # stratum -> repo -> [visible]
    repo_true = {}                                    # repo -> group (observed)
    for r in included_rows:
        by_sr[r["ecosystem_stratum"]][r["repo"]].append(1 if r["visible"] else 0)
        repo_true[r["repo"]] = r["group"]

    # Observed per-stratum stats (usable only).
    obs_terms, strata_detail = [], []
    for s in usable:
        reg = table[s]["registry"]
        nor = table[s]["no_registry"]
        n1, k1, n0, k0 = reg["adv"], reg["vis"], nor["adv"], nor["vis"]
        obs_terms.append((n1, k1, n0, k0))
        strata_detail.append({
            "stratum": s,
            "registry": {"repos": len(reg["repos"]), "adv": n1, "visible": k1,
                         "visible_pct": round(100 * k1 / n1, 1) if n1 else None},
            "no_registry": {"repos": len(nor["repos"]), "adv": n0, "visible": k0,
                            "visible_pct": round(100 * k0 / n0, 1) if n0 else None},
            "diff_pts": round(100 * ((k1 / n1) - (k0 / n0)), 1) if (n1 and n0) else None,
            "weight": round((n1 * n0) / (n1 + n0), 3) if (n1 + n0) else 0.0,
        })

    obs_rd = _mh_rd(obs_terms)
    obs_pts = round(100 * obs_rd, 2)

    distinct_repos = set()
    for s in usable:
        distinct_repos |= table[s]["registry"]["repos"] | table[s]["no_registry"]["repos"]

    underpowered = (len(usable) < MIN_USABLE_STRATA
                    or len(distinct_repos) < MIN_TOTAL_REPOS)

    # Within-stratum label permutation (independent per stratum).
    p_two = p_one = None
    if usable and not underpowered:
        # Pre-extract, per usable stratum, the repos present and their visibilities.
        packs = []
        for s in usable:
            repos = sorted(by_sr[s].keys())
            labels = [repo_true[rp] for rp in repos]
            vis = [by_sr[s][rp] for rp in repos]        # list of [0/1,...] per repo
            packs.append((repos, labels, vis))
        rng = random.Random(seed)
        eps = 1e-12
        ge_two = ge_one = 0
        for _ in range(n_perm):
            terms = []
            for repos, labels, vis in packs:
                perm = labels[:]
                rng.shuffle(perm)
                n1 = k1 = n0 = k0 = 0
                for lab, vlist in zip(perm, vis):
                    if lab == "registry":
                        n1 += len(vlist); k1 += sum(vlist)
                    else:
                        n0 += len(vlist); k0 += sum(vlist)
                terms.append((n1, k1, n0, k0))
            rd = _mh_rd(terms)
            if abs(rd) >= abs(obs_rd) - eps:
                ge_two += 1
            if rd >= obs_rd - eps:
                ge_one += 1
        p_two = ge_two / n_perm
        p_one = ge_one / n_perm

    if underpowered:
        verdict = "INCONCLUSIVE_UNDERPOWERED"
    elif obs_pts >= P1_MIN_POINTS and p_two is not None and p_two < P1_ALPHA:
        verdict = "SURVIVES"           # registry effect is not merely ecosystem coverage
    else:
        verdict = "DOES_NOT_SURVIVE"    # substantially a coverage confound

    return {
        "adjusted_difference_pts": obs_pts,
        "threshold_pts": P1_MIN_POINTS,
        "permutation_p_two_sided": p_two,
        "permutation_p_one_sided": p_one,
        "n_permutations": n_perm,
        "seed": seed,
        "usable_strata": usable,
        "usable_strata_count": len(usable),
        "distinct_repos_in_usable": sorted(distinct_repos),
        "distinct_repos_in_usable_count": len(distinct_repos),
        "power_floor": {
            "min_repos_per_group": MIN_REPOS_PER_GROUP,
            "min_usable_strata": MIN_USABLE_STRATA,
            "min_total_repos": MIN_TOTAL_REPOS,
            "underpowered": underpowered,
        },
        "strata_detail": strata_detail,
        "verdict": verdict,
    }


def compute_p2(included_rows, n_perm=N_PERM, seed=PERM_SEED):
    """P2: does ecosystem composition differ by group? Per-group stratum table
    plus a repository-level permutation test on each app's share of advisories in
    a well-indexed stratum."""
    # Per-app well-indexed share.
    apps = {}   # repo -> {"group", "total", "well"}
    for r in included_rows:
        a = apps.setdefault(r["repo"], {"group": r["group"], "total": 0, "well": 0})
        a["total"] += 1
        if r["ecosystem_stratum"] in WELL_INDEXED:
            a["well"] += 1
    repos = sorted(apps.keys())
    labels = [apps[rp]["group"] for rp in repos]
    shares = [apps[rp]["well"] / apps[rp]["total"] for rp in repos]

    reg_shares = [s for s, g in zip(shares, labels) if g == "registry"]
    nor_shares = [s for s, g in zip(shares, labels) if g == "no_registry"]
    diff_obs = (None if not reg_shares or not nor_shares
                else _mean(reg_shares) - _mean(nor_shares))

    p_two = None
    if diff_obs is not None:
        rng = random.Random(seed)
        eps = 1e-12
        ge = 0
        for _ in range(n_perm):
            perm = labels[:]
            rng.shuffle(perm)
            rs = [s for s, g in zip(shares, perm) if g == "registry"]
            ns = [s for s, g in zip(shares, perm) if g == "no_registry"]
            if not rs or not ns:
                continue
            d = _mean(rs) - _mean(ns)
            if abs(d) >= abs(diff_obs) - eps:
                ge += 1
        p_two = ge / n_perm

    # Per-group stratum table (advisory + repo counts).
    table = build_stratum_table(included_rows)
    group_table = {}
    for stratum in sorted(table.keys()):
        group_table[stratum] = {
            "registry": {"adv": table[stratum]["registry"]["adv"],
                         "repos": len(table[stratum]["registry"]["repos"])},
            "no_registry": {"adv": table[stratum]["no_registry"]["adv"],
                            "repos": len(table[stratum]["no_registry"]["repos"])},
        }

    return {
        "well_indexed_set": list(WELL_INDEXED),
        "n_apps_with_eligible_advisories": len(repos),
        "n_registry_apps": sum(1 for g in labels if g == "registry"),
        "n_no_registry_apps": sum(1 for g in labels if g == "no_registry"),
        "mean_well_indexed_share_registry": (round(_mean(reg_shares), 4)
                                             if reg_shares else None),
        "mean_well_indexed_share_no_registry": (round(_mean(nor_shares), 4)
                                                if nor_shares else None),
        "share_difference": (round(diff_obs, 4) if diff_obs is not None else None),
        "permutation_p_two_sided": p_two,
        "per_group_stratum_table": group_table,
    }


def compute_p3(included_rows):
    """P3: OSV visible-rate by ecosystem stratum, pooled over both groups."""
    pooled = defaultdict(lambda: {"n": 0, "k": 0})
    for r in included_rows:
        c = pooled[r["ecosystem_stratum"]]
        c["n"] += 1
        c["k"] += 1 if r["visible"] else 0
    out = {}
    for stratum in sorted(pooled.keys()):
        n, k = pooled[stratum]["n"], pooled[stratum]["k"]
        out[stratum] = {"n": n, "visible": k,
                        "visible_pct": round(100 * k / n, 1) if n else None,
                        "ci95": wilson(k, n)}
    return out


def run_analysis(rows, n_perm=N_PERM, seed=PERM_SEED):
    included = [r for r in rows if r["included"]]
    excluded_other = sum(1 for r in rows if not r["included"])
    pt_counts = defaultdict(int)
    for r in rows:
        pt_counts[r["advisory_product_type"] or "(blank)"] += 1
    return {
        "frame_apps": len(set(r["repo"] for r in rows)),
        "eligible_advisories_in_frame": len(rows),
        "included_advisories": len(included),
        "excluded_other": excluded_other,
        "product_type_counts": dict(pt_counts),
        "P1_adjusted": compute_p1(included, n_perm, seed),
        "P2_composition": compute_p2(included, n_perm, seed),
        "P3_osv_coverage_by_ecosystem": compute_p3(included),
    }


# --------------------------------------------------------------------------- #
# I/O.                                                                         #
# --------------------------------------------------------------------------- #

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_census_csv(rows, out_path):
    cols = ["repo", "group", "ghsa_id", "cve_id", "advisory_product_type",
            "advisory_ecosystems", "named_packages", "named_pkg_resolution",
            "real_package", "scanner_class", "visible", "ecosystem_stratum",
            "stratum_source", "included"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in cols})


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--census-csv", required=True,
                    help="A4's real_package_census.csv")
    ap.add_argument("--classification", required=True,
                    help="registry_classification.json (the 32-app frame)")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--n-perm", type=int, default=N_PERM)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    classification = load_classification(args.classification)
    rows, skipped = load_rows(args.census_csv, classification)
    summary = run_analysis(rows, n_perm=args.n_perm, seed=PERM_SEED)

    with open(os.path.join(args.out_dir, "ecosystem_adjusted_summary.json"),
              "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    write_census_csv(rows, os.path.join(args.out_dir, "ecosystem_census.csv"))

    meta = {
        "study": "registry-channel E1 -- ecosystem-coverage confound",
        "input_census_csv": os.path.basename(args.census_csv),
        "input_census_sha256": _sha256(args.census_csv),
        "input_classification": os.path.basename(args.classification),
        "input_classification_sha256": _sha256(args.classification),
        "classification_apps": len(classification),
        "rows_off_frame_skipped": skipped,
        "seed": PERM_SEED,
        "n_permutations": args.n_perm,
        "well_indexed_set": list(WELL_INDEXED),
        "thresholds": {"p1_min_points": P1_MIN_POINTS, "p1_alpha": P1_ALPHA,
                       "min_repos_per_group": MIN_REPOS_PER_GROUP,
                       "min_usable_strata": MIN_USABLE_STRATA,
                       "min_total_repos": MIN_TOTAL_REPOS},
        "note": ("E1 is a re-analysis of A4's census: no new collection, no "
                 "network, no compute job. Analysis code frozen before A4's data "
                 "existed. Made with AI agents working for MV2 of Munim, Inc.; "
                 "no result reviewed by a human."),
    }
    with open(os.path.join(args.out_dir, "ecosystem_adjusted_meta.json"),
              "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    p1 = summary["P1_adjusted"]
    print("[e1] apps=%d eligible=%d included=%d excluded_other=%d"
          % (summary["frame_apps"], summary["eligible_advisories_in_frame"],
             summary["included_advisories"], summary["excluded_other"]), flush=True)
    print("[e1] usable_strata=%d (%s) distinct_repos=%d"
          % (p1["usable_strata_count"], ",".join(p1["usable_strata"]) or "-",
             p1["distinct_repos_in_usable_count"]), flush=True)
    print("[e1] adjusted_diff=%s pts  p2sided=%s  verdict=%s"
          % (p1["adjusted_difference_pts"], p1["permutation_p_two_sided"],
             p1["verdict"]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
