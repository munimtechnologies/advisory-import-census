"""Go-module-rescue census for the advisory-import gap (registry-channel A5).

Background. A3 showed that *naming a package on the GitHub advisory page* explains
only about a third of the registry-channel visibility gap. Its residuals held a
sharp pattern: among SOFTWARE-typed advisories -- those where the maintainer named
no package at all on the page -- the ones that still reach OSV-backed scanners are
overwhelmingly Go projects (grafana, harbor, authentik...), where OSV names the
module `github.com/<owner>/<repo>`, while the blind software-typed advisories sit in
Ruby/Python/Node/C++ apps (discourse, mastodon, zulip, ClickHouse...). The
hypothesised reason: GitHub's advisory reviewers can attach a Go module to the
global, OSV-indexed record *for free*, because Go's import-path == repo-path
convention needs no package-registry publication at all -- so a Go project is
rescued even when it has no "registry" app release in the A1/A2 sense (grafana is
`no_registry`, yet its advisories carry `Go:github.com/grafana/grafana`).

A5 quantifies that channel. For every repository in the FROZEN software-typed frame
(the `advisory_product_type == software` rows of A3's public census) it probes, from
two independent public sources, whether the repository is a Go module at its own
repo path, then joins that per-repo covariate to A3's frozen visibility measure.

Pre-registration: PREREGISTRATION-registry-channel-a5.md (frozen before this ran).
The go-module covariate comes from go.mod / the Go module proxy -- data sources
entirely independent of the OSV visibility measure, so the test is non-circular.

Public read-only data only; no account, no writes; paced. stdlib only. The fetched
census and every probe response are archived to /out so any row can be re-audited.
Apache-2.0, made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

CENSUS_URL = ("https://raw.githubusercontent.com/munimtechnologies/"
              "advisory-import-census/main/study/registry-channel-a3/"
              "attribution_census.csv")
UA = "mv2-advisory-import-census-a5 (+https://github.com/munimtechnologies)"
PROXY = "https://proxy.golang.org"
RAW = "https://raw.githubusercontent.com"
PROBE_BRANCHES = ("main", "master")  # tried in order for go.mod


# --------------------------------------------------------------------------
# HTTP (paced, read-only, stdlib)
# --------------------------------------------------------------------------

def _get(url, pace=1.0, timeout=30):
    """GET a URL. Returns (status, text). Non-2xx is returned as (code, body),
    never raised, so an absent go.mod (404) is a datum, not a crash."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            status = r.getcode()
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            body = e.read().decode("utf-8", "replace")
        except Exception:
            body = ""
    except (urllib.error.URLError, TimeoutError) as e:
        status = -1
        body = "URLERROR:%s" % (e,)
    time.sleep(pace)
    return status, body


# --------------------------------------------------------------------------
# Go-module probes (pure helpers below are unit-tested offline)
# --------------------------------------------------------------------------

def go_proxy_escape(path):
    """Go module proxy case-encoding: each uppercase letter X -> '!x'."""
    out = []
    for ch in path:
        if ch.isupper():
            out.append("!" + ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def parse_module_line(gomod_text):
    """Return the module path from a go.mod, or None. Handles the `module path`
    form and a `module (` block's first path; strips quotes and a comment."""
    if not gomod_text:
        return None
    lines = gomod_text.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("module"):
            rest = s[len("module"):].strip()
            if rest == "(":  # rare block form: path on the next line
                for j in range(i + 1, len(lines)):
                    t = lines[j].strip()
                    if t and t != ")":
                        rest = t
                        break
            rest = rest.split("//", 1)[0].strip().strip('"')
            return rest or None
    return None


def module_path_is_repo(module_path, repo):
    """True iff module_path is github.com/<repo> at its root (allowing a trailing
    major-version suffix like /v2), case-insensitive. Guards against a sibling repo
    whose name is a prefix (e.g. .../name vs .../name-extra)."""
    if not module_path:
        return False
    m = module_path.lower().rstrip("/")
    want = ("github.com/" + repo).lower()
    return m == want or m.startswith(want + "/")


def decide_go_module(gomod_match, proxy_ok):
    """A repo is a Go module at its repo path iff go.mod proves it OR the Go proxy
    serves a version for github.com/<repo>. Either independent source suffices."""
    return bool(gomod_match or proxy_ok)


def probe_repo(repo, pace=1.0):
    """Probe one owner/name repository for go-module-at-repo-path, recording both
    signals and any disagreement."""
    owner_name = repo
    # 1) go.mod on the default branch (try main then master).
    gomod_module = None
    gomod_branch = ""
    gomod_status = None
    for br in PROBE_BRANCHES:
        st, body = _get("%s/%s/%s/go.mod" % (RAW, owner_name, br), pace=pace)
        gomod_status = st
        if st == 200:
            gomod_module = parse_module_line(body)
            gomod_branch = br
            break
    gomod_match = module_path_is_repo(gomod_module, repo)
    # 2) Go module proxy @latest for github.com/<repo>.
    escaped = go_proxy_escape("github.com/" + owner_name)
    pst, pbody = _get("%s/%s/@latest" % (PROXY, escaped), pace=pace)
    proxy_version = ""
    if pst == 200:
        try:
            proxy_version = json.loads(pbody).get("Version", "") or ""
        except Exception:
            proxy_version = ""
    proxy_ok = (pst == 200 and bool(proxy_version))
    return {
        "repo": repo,
        "gomod_branch": gomod_branch,
        "gomod_status": gomod_status,
        "gomod_module": gomod_module or "",
        "gomod_match": gomod_match,
        "proxy_status": pst,
        "proxy_version": proxy_version,
        "proxy_ok": proxy_ok,
        "go_module": decide_go_module(gomod_match, proxy_ok),
    }


# --------------------------------------------------------------------------
# Census load + join
# --------------------------------------------------------------------------

def load_census_text(args):
    if args.census_file:
        with open(args.census_file, encoding="utf-8") as f:
            return f.read()
    st, body = _get(args.census_url, pace=0.0)
    if st != 200:
        raise SystemExit("could not fetch census (%s): HTTP %s" % (args.census_url, st))
    return body


def load_classification(path):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    return {k: v["group"] for k, v in doc["classification"].items()}, doc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--census-url", default=CENSUS_URL)
    ap.add_argument("--census-file", default=None,
                    help="offline override; if set, no census fetch")
    ap.add_argument("--classification", default="registry_classification.json")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--pace", type=float, default=1.0)
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    census_text = load_census_text(args)
    census_sha = hashlib.sha256(census_text.encode("utf-8")).hexdigest()
    with open(os.path.join(args.out_dir, "a3_census_snapshot.csv"), "w",
              encoding="utf-8", newline="") as f:
        f.write(census_text)

    all_rows = list(csv.DictReader(census_text.splitlines()))
    soft = [r for r in all_rows if r["advisory_product_type"] == "software"]
    reg_map, reg_doc = load_classification(args.classification)

    repos = sorted({r["repo"] for r in soft})
    unclassified = [r for r in repos if r not in reg_map]
    if unclassified:
        raise SystemExit("software-typed repos missing from classification: %s"
                         % ", ".join(unclassified))

    print("software-typed advisories: %d across %d repos" % (len(soft), len(repos)),
          flush=True)

    probes = {}
    for repo in repos:
        p = probe_repo(repo, pace=args.pace)
        p["registry_group"] = reg_map[repo]
        probes[repo] = p
        print("  %-32s go_module=%s (gomod=%s@%s match=%s | proxy=%s %s)" % (
            repo, p["go_module"], p["gomod_module"] or "-", p["gomod_branch"] or "-",
            p["gomod_match"], p["proxy_status"], p["proxy_version"] or "-"),
            flush=True)

    # Per-advisory census (software-typed rows + the per-repo covariate).
    cen_path = os.path.join(args.out_dir, "go_rescue_census.csv")
    cols = ["registry_group", "repo", "ghsa_id", "cve_id", "scanner_class",
            "osv_packages", "advisory_ecosystems", "go_module", "gomod_module",
            "gomod_branch", "proxy_status", "proxy_version"]
    with open(cen_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in soft:
            p = probes[r["repo"]]
            w.writerow({
                "registry_group": p["registry_group"],
                "repo": r["repo"],
                "ghsa_id": r["ghsa_id"],
                "cve_id": r["cve_id"],
                "scanner_class": r["scanner_class"],
                "osv_packages": r["osv_packages"],
                "advisory_ecosystems": r["advisory_ecosystems"],
                "go_module": p["go_module"],
                "gomod_module": p["gomod_module"],
                "gomod_branch": p["gomod_branch"],
                "proxy_status": p["proxy_status"],
                "proxy_version": p["proxy_version"],
            })

    # Per-repo probe table.
    probe_path = os.path.join(args.out_dir, "go_rescue_repo_probe.csv")
    pcols = ["repo", "registry_group", "n_software_adv", "go_module", "gomod_match",
             "gomod_module", "gomod_branch", "gomod_status", "proxy_status",
             "proxy_version", "proxy_ok"]
    counts = {}
    for r in soft:
        counts[r["repo"]] = counts.get(r["repo"], 0) + 1
    with open(probe_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=pcols)
        w.writeheader()
        for repo in repos:
            p = probes[repo]
            w.writerow({
                "repo": repo, "registry_group": p["registry_group"],
                "n_software_adv": counts[repo], "go_module": p["go_module"],
                "gomod_match": p["gomod_match"], "gomod_module": p["gomod_module"],
                "gomod_branch": p["gomod_branch"], "gomod_status": p["gomod_status"],
                "proxy_status": p["proxy_status"], "proxy_version": p["proxy_version"],
                "proxy_ok": p["proxy_ok"],
            })

    meta = {
        "study": "registry-channel A5 (go-module reviewer-rescue of software-typed advisories)",
        "census_source": args.census_file or args.census_url,
        "census_sha256": census_sha,
        "classification_frozen_utc": reg_doc.get("frozen_utc"),
        "n_all_advisories": len(all_rows),
        "n_software_typed": len(soft),
        "n_repos": len(repos),
        "n_go_module_repos": sum(1 for p in probes.values() if p["go_module"]),
        "n_not_go_repos": sum(1 for p in probes.values() if not p["go_module"]),
        "gomod_proxy_disagreements": [
            {"repo": p["repo"], "gomod_match": p["gomod_match"], "proxy_ok": p["proxy_ok"]}
            for p in probes.values() if p["gomod_match"] != p["proxy_ok"]
        ],
    }
    with open(os.path.join(args.out_dir, "go_rescue_census_meta.json"), "w",
              encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print("meta:", json.dumps(meta, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
