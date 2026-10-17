"""Build the frozen sampling frame for MV2's pre-registered application-vs-library
advisory-import-gap census.

Selection is BLINDNESS-INDEPENDENT and ADVISORY-INDEPENDENT: applications are
ranked only by the star count already recorded in awesome-selfhosted-data's own
YAML (no GitHub call), libraries only by their dependent count from the public,
keyless ecosyste.ms API. Nothing here looks at whether an advisory is visible to
a scanner, so the frame cannot be gamed toward the hypothesis. The census
(app_library_census.py) decides which selected repos actually have advisories;
repos with none stay in the frame but contribute no eligible rows.

The exclusion set is derived reproducibly from the already-published census
dataset committed in the repo (study/2026-10-17/group_census.csv, shipped in
v0.9.0): every repository used in census v0.1 or the AI-vs-control study is
excluded, so this is a genuinely fresh sample.

Outputs (to --out-dir): frame_apps.json, frame_libs.json, frame_exclude.txt,
frame_used.json. Stdlib only. Apache-2.0, made with AI agents working for MV2 of
Munim, Inc.
"""
import argparse
import csv
import datetime as dt
import glob
import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request

UA = "advisory-import-census-frame (MV2 of Munim, Inc.)"
TARGET_N = 40  # top-N per group selected by the blindness-independent criterion

CENSUS_TARBALL = ("https://codeload.github.com/munimtechnologies/"
                  "advisory-import-census/tar.gz/refs/heads/main")
CENSUS_CSV_REL = "study/2026-10-17/group_census.csv"

ASH_TARBALL = ("https://codeload.github.com/awesome-selfhosted/"
               "awesome-selfhosted-data/tar.gz/refs/heads/master")

ECOSYSTEMS = "https://packages.ecosyste.ms/api/v1/registries/%s/packages"
LIB_REGISTRIES = ["npmjs.org", "pypi.org", "proxy.golang.org"]

GH_RE = re.compile(r"github\.com[:/]+([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def http_bytes(url, timeout=180, tries=4):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.URLError, TimeoutError) as e:
            if i == tries - 1:
                raise
            print("[frame] retry %s (%s)" % (url, e), flush=True)
            time.sleep(2 ** i)


def http_json(url, timeout=120, tries=4):
    return json.loads(http_bytes(url, timeout=timeout, tries=tries).decode("utf-8"))


def normalize_repo(url):
    """A GitHub 'owner/repo' (lowercased, .git stripped) from any github URL, else None."""
    if not url:
        return None
    m = GH_RE.search(url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if repo in (".", "..") or owner in ("sponsors", "orgs", "topics"):
        return None
    return "%s/%s" % (owner, repo)


# ---------------------------------------------------------------- YAML (minimal)

def parse_flat_yaml(text):
    """Top-level scalar keys only from an awesome-selfhosted-data entry.

    Enough for name / source_code_url / stargazers_count / archived, which are all
    top-level scalars. Block values (a key with an empty value followed by indented
    lines, e.g. 'tags:') are skipped. No external dependency."""
    out = {}
    for line in text.splitlines():
        if not line or line[0] in " \t#":
            continue  # indented (part of a block) or comment
        m = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if val == "":
            continue  # start of a block list/map; not a scalar we need
        if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
            val = val[1:-1]
        out[key] = val
    return out


def _as_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _as_bool(v):
    return str(v).strip().lower() in ("true", "yes", "1")


# ------------------------------------------------------------------- exclude set

def build_exclude(workdir):
    data = http_bytes(CENSUS_TARBALL)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(workdir, filter="data")
    roots = [d for d in glob.glob(os.path.join(workdir, "*")) if os.path.isdir(d)]
    assert roots, "census tarball extracted no directory"
    csv_path = os.path.join(roots[0], CENSUS_CSV_REL)
    excl = set()
    with open(csv_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            repo = (r.get("repo") or "").strip()
            if repo:
                excl.add(repo.lower())
    assert excl, "no repos read from census csv"
    return excl


# -------------------------------------------------------------------- app frame

def build_apps(workdir, exclude):
    data = http_bytes(ASH_TARBALL)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(workdir, filter="data")
    roots = [d for d in glob.glob(os.path.join(workdir, "awesome-selfhosted-data*"))
             if os.path.isdir(d)]
    assert roots, "awesome-selfhosted-data tarball extracted no directory"
    sw_dir = os.path.join(roots[0], "software")
    files = sorted(glob.glob(os.path.join(sw_dir, "*.yml")))
    assert files, "no software/*.yml found"

    cands = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            entry = parse_flat_yaml(f.read())
        repo = normalize_repo(entry.get("source_code_url"))
        stars = _as_int(entry.get("stargazers_count"))
        if not repo or stars is None:
            continue
        if _as_bool(entry.get("archived")):
            continue
        if repo.lower() in exclude:
            continue
        cands.append({"repo": repo, "stars": stars,
                      "name": entry.get("name", ""),
                      "source_file": os.path.basename(path)})
    # dedupe by repo, keep the highest star count seen
    best = {}
    for c in cands:
        k = c["repo"].lower()
        if k not in best or c["stars"] > best[k]["stars"]:
            best[k] = c
    ranked = sorted(best.values(), key=lambda c: (-c["stars"], c["repo"].lower()))
    return ranked[:TARGET_N], len(best)


# -------------------------------------------------------------------- lib frame

def _dependents_metric(pkg):
    """Best available dependents figure for the record, or (None, None).

    The listing endpoint may omit these; selection does NOT depend on them (it
    trusts the server-side sort), they are only recorded for transparency."""
    for key in ("dependent_repos_count", "dependent_packages_count", "downloads"):
        v = pkg.get(key)
        if isinstance(v, (int, float)):
            return key, int(v)
    return None, None


def _lib_archived(pkg):
    rm = pkg.get("repo_metadata") or {}
    return bool(rm.get("archived"))


def _registry_ranked(reg, exclude, metric_counts):
    """Ordered, de-duplicated github repos for one registry, highest dependents
    first. Order is the server-side sort (sort=dependent_repos_count&order=desc),
    so it holds even when the listing payload omits the dependents field."""
    seen = set()
    out = []
    for page in (1, 2, 3):
        url = ("%s?sort=dependent_repos_count&order=desc&per_page=100&page=%d"
               % (ECOSYSTEMS % reg, page))
        try:
            pkgs = http_json(url)
        except Exception as e:
            print("[frame] lib registry %s page %d failed: %s" % (reg, page, e),
                  flush=True)
            break
        if not isinstance(pkgs, list) or not pkgs:
            break
        for p in pkgs:
            repo = normalize_repo(p.get("repository_url"))
            if not repo or repo.lower() in exclude or _lib_archived(p):
                continue
            k = repo.lower()
            if k in seen:
                continue
            seen.add(k)
            metric_key, metric_val = _dependents_metric(p)
            if metric_key:
                metric_counts[metric_key] = metric_counts.get(metric_key, 0) + 1
            out.append({"repo": repo, "registry": reg, "package": p.get("name", ""),
                        "metric": metric_key, "dependents": metric_val,
                        "registry_rank": len(out) + 1})
        time.sleep(0.3)
    return out


def build_libs(exclude):
    """Top libraries by dependents, balanced across registries by round-robin on
    each registry's own dependents ranking (so the library group is not dominated
    by a single ecosystem). De-duplicated across registries (first seen wins)."""
    metric_counts = {}
    ranked_per_reg = {reg: _registry_ranked(reg, exclude, metric_counts)
                      for reg in LIB_REGISTRIES}
    chosen, taken = [], set()
    depth = max((len(v) for v in ranked_per_reg.values()), default=0)
    for i in range(depth):
        for reg in LIB_REGISTRIES:
            lst = ranked_per_reg[reg]
            if i < len(lst) and lst[i]["repo"].lower() not in taken:
                taken.add(lst[i]["repo"].lower())
                chosen.append(lst[i])
                if len(chosen) >= TARGET_N:
                    break
        if len(chosen) >= TARGET_N:
            break
    diag = {"per_registry_candidates": {r: len(v) for r, v in ranked_per_reg.items()},
            "metric_field_counts": metric_counts,
            "unique_repo_candidates": sum(len(v) for v in ranked_per_reg.values())}
    return chosen, diag


# -------------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--work-dir", default="/tmp/aic-frame")
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)
    os.makedirs(args.work_dir, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

    print("[frame] building exclude set from published census csv", flush=True)
    exclude = build_exclude(args.work_dir)
    print("[frame] exclude: %d repos" % len(exclude), flush=True)

    print("[frame] building application frame (awesome-selfhosted stars)", flush=True)
    apps, n_app_cand = build_apps(args.work_dir, exclude)
    print("[frame] apps: %d selected of %d candidates" % (len(apps), n_app_cand),
          flush=True)

    print("[frame] building library frame (ecosyste.ms dependents)", flush=True)
    libs, lib_diag = build_libs(exclude)
    print("[frame] libs: %d selected of %d candidates"
          % (len(libs), lib_diag["unique_repo_candidates"]), flush=True)

    with open(os.path.join(args.out_dir, "frame_apps.json"), "w", encoding="utf-8") as f:
        json.dump(apps, f, indent=2)
    with open(os.path.join(args.out_dir, "frame_libs.json"), "w", encoding="utf-8") as f:
        json.dump(libs, f, indent=2)
    with open(os.path.join(args.out_dir, "frame_exclude.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(exclude)) + "\n")

    used = {
        "built_utc": now,
        "target_n_per_group": TARGET_N,
        "selection": {
            "applications": "awesome-selfhosted-data source_code_url on github, "
                            "not archived, ranked by stargazers_count desc",
            "libraries": "ecosyste.ms packages across %s, mapped to github "
                         "repository_url, ranked by dependent_repos_count desc"
                         % ", ".join(LIB_REGISTRIES),
        },
        "sources": {"census_exclude": CENSUS_TARBALL,
                    "apps": ASH_TARBALL,
                    "libs_registries": LIB_REGISTRIES},
        "counts": {"exclude": len(exclude),
                   "app_candidates": n_app_cand, "apps_selected": len(apps),
                   "libs_selected": len(libs)},
        "lib_diagnostics": lib_diag,
        "note": "Selection is blindness- and advisory-independent; the census "
                "determines which selected repos have eligible advisories.",
    }
    with open(os.path.join(args.out_dir, "frame_used.json"), "w", encoding="utf-8") as f:
        json.dump(used, f, indent=2)

    print("[frame] wrote frame_apps.json (%d), frame_libs.json (%d), "
          "frame_exclude.txt (%d), frame_used.json"
          % (len(apps), len(libs), len(exclude)), flush=True)
    if len(apps) < 10 or len(libs) < 10:
        print("[frame] WARNING: a group has < 10 repos; inspect before the census",
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
