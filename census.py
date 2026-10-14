#!/usr/bin/env python3
"""GRA census: how many maintainer-published repository security advisories
(GRAs) for popular self-hosted AI/ML tooling never reach GitHub's global
Advisory Database under their own GHSA ID, and for how long.

Made with AI agents working for MV2 of Munim, Inc. Apache-2.0.

Method (all public, unauthenticated, read-only metadata):
  1. List each target repo's published security advisories via the public
     REST endpoint GET /repos/{owner}/{repo}/security-advisories.
  2. Build the set of GHSA IDs present in github/advisory-database from a
     blobless, no-checkout clone (git ls-tree gives every filename = every
     GHSA ID without downloading the ~600 MB of JSON blobs).
  3. For each GRA, check whether its own GHSA ID is a file in the global DB.
     Those absent are "not imported under their own ID" (censored in the
     sense of the arXiv 2602.06009 pipeline study, which only collects GRAs
     reachable through repository_advisory_url and so cannot see them).
  4. For the absent subset, ask the global API whether the GRA's CVE has ANY
     global coverage (usually a thin NVD-sourced record under a different
     GHSA). This separates "only a thin NVD record exists" from "no global
     presence at all" -- the Dependabot-blind case MV2 documented for Flowise.

Honest limits: a sample of repos; a single snapshot date; GHSA-ID membership
can miss a GRA that was re-imported under a different GHSA with the same
content; curation lag may be intentional for some ecosystems; unauthenticated
API data only.
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

UA = "mv2-munim-gra-census (open-source research; contact munimversion2@gmail.com)"
GHSA_RE = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}")

# Popular self-hosted AI/ML tooling repos (the ecosystem MV2's
# dependabot-blind-ai-advisories page already tracks, widened).
TARGET_REPOS = [
    "FlowiseAI/Flowise",
    "langgenius/dify",
    "langflow-ai/langflow",
    "vllm-project/vllm",
    "comfyanonymous/ComfyUI",
    "open-webui/open-webui",
    "BerriAI/litellm",
    "sgl-project/sglang",
    "invoke-ai/InvokeAI",
    "oobabooga/text-generation-webui",
    "mudler/LocalAI",
    "infiniflow/ragflow",
    "Mintplex-Labs/anything-llm",
    "danny-avila/LibreChat",
    "h2oai/h2ogpt",
    "mlflow/mlflow",
    "ray-project/ray",
    "gradio-app/gradio",
    "run-llama/llama_index",
    "langchain-ai/langchain",
    "mem0ai/mem0",
    "zylon-ai/private-gpt",
    "deepset-ai/haystack",
    "microsoft/autogen",
    "crewAIInc/crewAI",
    "xorbitsai/inference",
    "huggingface/transformers",
    "feast-dev/feast",
    "bentoml/BentoML",
    "zenml-io/zenml",
]


def api_get(url, retries=5):
    """GET JSON from the GitHub REST API, unauthenticated, honouring the
    hourly rate limit by sleeping until reset on 403/429."""
    for attempt in range(retries):
        req = urllib.request.Request(url, headers={
            "User-Agent": UA,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read().decode("utf-8")
                link = resp.headers.get("Link", "")
                return json.loads(body), link, resp.status
        except urllib.error.HTTPError as e:
            remaining = e.headers.get("X-RateLimit-Remaining")
            reset = e.headers.get("X-RateLimit-Reset")
            if e.code in (403, 429) and remaining == "0" and reset:
                wait = max(1, int(reset) - int(time.time())) + 3
                print(f"  rate limited; sleeping {wait}s until reset", flush=True)
                time.sleep(min(wait, 3700))
                continue
            if e.code == 404:
                return None, "", 404
            print(f"  HTTP {e.code} for {url}: {e.reason}", flush=True)
            time.sleep(5 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError) as e:
            print(f"  network error for {url}: {e}", flush=True)
            time.sleep(5 * (attempt + 1))
    return None, "", 0


def next_link(link_header):
    for part in link_header.split(","):
        seg = part.split(";")
        if len(seg) >= 2 and 'rel="next"' in seg[1]:
            return seg[0].strip().strip("<>")
    return None


def list_repo_advisories(repo):
    """Return every published security advisory for a repo."""
    out = []
    url = (f"https://api.github.com/repos/{repo}/security-advisories"
           f"?state=published&per_page=100")
    while url:
        data, link, status = api_get(url)
        if data is None:
            print(f"  {repo}: no data (status {status})", flush=True)
            break
        if isinstance(data, dict):  # error object
            print(f"  {repo}: {data.get('message')}", flush=True)
            break
        out.extend(data)
        url = next_link(link)
    return out


def build_global_ghsa_index(advdb_dir):
    """Map every GHSA ID in github/advisory-database to its repo path and
    whether it sits under github-reviewed/ or unreviewed/."""
    res = subprocess.run(
        ["git", "-C", advdb_dir, "ls-tree", "-r", "--name-only", "HEAD"],
        capture_output=True, text=True, check=True)
    index = {}
    for path in res.stdout.splitlines():
        if not path.endswith(".json"):
            continue
        m = GHSA_RE.search(os.path.basename(path))
        if not m:
            continue
        ghsa = m.group(0)
        reviewed = "/github-reviewed/" in path
        # Prefer a reviewed path if the same id appears twice.
        if ghsa not in index or reviewed:
            index[ghsa] = {"path": path, "reviewed": reviewed}
    return index


def read_reviewed_at(advdb_dir, path):
    """Lazily fetch just one blob from the blobless clone and read
    github_reviewed_at / database_specific timestamps."""
    try:
        res = subprocess.run(
            ["git", "-C", advdb_dir, "cat-file", "-p", f"HEAD:{path}"],
            capture_output=True, text=True, check=True)
        obj = json.loads(res.stdout)
        ds = obj.get("database_specific", {}) or {}
        return ds.get("github_reviewed_at") or ds.get("nvd_published_at")
    except Exception as e:
        print(f"  could not read {path}: {e}", flush=True)
        return None


def cve_has_global_coverage(cve_id):
    """Does the global DB have ANY record for this CVE (usually a thin
    NVD-sourced one under a different GHSA)?"""
    if not cve_id:
        return None
    url = f"https://api.github.com/advisories?cve_id={cve_id}&per_page=1"
    data, _, status = api_get(url)
    if isinstance(data, list):
        return len(data) > 0
    return None


def days_between(a_iso, b_dt):
    try:
        a = datetime.fromisoformat(a_iso.replace("Z", "+00:00"))
    except Exception:
        return None
    return round((b_dt - a).total_seconds() / 86400.0, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--advdb", required=True, help="path to blobless clone of github/advisory-database")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)
    snapshot = datetime.now(timezone.utc)

    print("Building global GHSA index from advisory-database clone...", flush=True)
    index = build_global_ghsa_index(args.advdb)
    print(f"  global DB contains {len(index)} GHSA records", flush=True)

    rows = []
    for repo in TARGET_REPOS:
        print(f"Listing advisories for {repo}...", flush=True)
        advs = list_repo_advisories(repo)
        print(f"  {len(advs)} published advisories", flush=True)
        for a in advs:
            ghsa = a.get("ghsa_id")
            cve = a.get("cve_id")
            pub = a.get("published_at")
            hit = index.get(ghsa)
            imported = hit is not None
            reviewed_at = None
            days = None
            if imported and hit["reviewed"]:
                reviewed_at = read_reviewed_at(args.advdb, hit["path"])
                if reviewed_at and pub:
                    days = days_between(pub, datetime.fromisoformat(
                        reviewed_at.replace("Z", "+00:00")))
            days_missing = days_between(pub, snapshot) if (not imported and pub) else None
            rows.append({
                "repo": repo,
                "ghsa_id": ghsa,
                "cve_id": cve or "",
                "severity": a.get("severity") or "",
                "published_at": pub or "",
                "state": a.get("state") or "",
                "in_global_db": imported,
                "global_path_kind": ("reviewed" if (imported and hit["reviewed"])
                                     else "unreviewed" if imported else ""),
                "github_reviewed_at": reviewed_at or "",
                "days_to_import": days if days is not None else "",
                "days_missing": days_missing if days_missing is not None else "",
                "cve_global_coverage": "",  # filled below for censored subset
            })

    # For the censored subset (GRA absent under its own GHSA), check whether
    # the CVE has any global coverage at all.
    censored = [r for r in rows if not r["in_global_db"]]
    print(f"Checking CVE global coverage for {len(censored)} censored GRAs...", flush=True)
    for r in censored:
        cov = cve_has_global_coverage(r["cve_id"]) if r["cve_id"] else None
        r["cve_global_coverage"] = ("" if cov is None else ("yes" if cov else "no"))

    # Write dataset CSV.
    csv_path = os.path.join(args.out_dir, "gra_census.csv")
    fields = list(rows[0].keys()) if rows else []
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    # Summary.
    total = len(rows)
    imported_rows = [r for r in rows if r["in_global_db"]]
    reviewed_rows = [r for r in imported_rows if r["global_path_kind"] == "reviewed"]
    unreviewed_rows = [r for r in imported_rows if r["global_path_kind"] == "unreviewed"]
    missing_days = sorted(r["days_missing"] for r in censored
                          if isinstance(r["days_missing"], (int, float)))
    cve_only_nvd = [r for r in censored if r["cve_global_coverage"] == "yes"]
    cve_absent = [r for r in censored if r["cve_global_coverage"] == "no"]

    def median(xs):
        if not xs:
            return None
        n = len(xs)
        return xs[n // 2] if n % 2 else round((xs[n // 2 - 1] + xs[n // 2]) / 2, 1)

    per_repo = {}
    for r in rows:
        d = per_repo.setdefault(r["repo"], {"total": 0, "censored": 0})
        d["total"] += 1
        if not r["in_global_db"]:
            d["censored"] += 1

    summary = {
        "snapshot_utc": snapshot.isoformat(),
        "global_db_ghsa_count": len(index),
        "repos_surveyed": len(TARGET_REPOS),
        "total_published_gras": total,
        "in_global_db": len(imported_rows),
        "in_global_db_reviewed": len(reviewed_rows),
        "in_global_db_unreviewed": len(unreviewed_rows),
        "not_in_global_db_by_own_ghsa": len(censored),
        "censored_with_only_nvd_cve_record": len(cve_only_nvd),
        "censored_with_no_global_presence": len(cve_absent),
        "median_days_missing": median(missing_days),
        "max_days_missing": max(missing_days) if missing_days else None,
        "median_days_to_import_when_reviewed": median(sorted(
            r["days_to_import"] for r in reviewed_rows
            if isinstance(r["days_to_import"], (int, float)))),
        "per_repo": per_repo,
    }
    with open(os.path.join(args.out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2), flush=True)
    print(f"Wrote {csv_path} ({total} rows) and summary.json", flush=True)


if __name__ == "__main__":
    main()
