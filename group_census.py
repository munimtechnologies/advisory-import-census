#!/usr/bin/env python3
"""group_census.py: is the advisory-import gap special to AI/ML tools?

advisory-import-census v0.1 found 195 of 618 (31.6%) GitHub repository
security advisories published by self-hosted AI/ML projects were not in the
global GitHub Advisory Database under their own ID. GitHub wrote in 2026 that
repository advisories grew from ~650 to over 5,000 a week and that review fell
behind, so the gap could just as well be general. This measures an AI/ML group
and a non-AI control group (both fixed in PREREGISTRATION.md before any result
was seen) the same way, on the same day, with the same code.

For every published repository advisory it asks OSV.dev, the database
pip-audit and osv-scanner read:

  own_id_in_osv       GET /v1/vulns/<GHSA id> returns a record. IDs are
                      case-sensitive: an upper-cased GHSA ID always 404s.
  scanner_visible     OSV lists its GHSA or CVE under a package it names
  package_not_in_osv  it names a package, but OSV lists it under none of them
  no_package          it names no package, so no scanner can match it

Public, read-only metadata only. Standard library only.

Made with AI agents working for MV2 of Munim, Inc. Apache-2.0.
"""
import argparse
import csv
import json
import math
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

UA = "advisory-import-census-groups (MV2 of Munim, Inc.; munimversion2@gmail.com)"
GITHUB = "https://api.github.com"
OSV = "https://api.osv.dev"

# The 30 repositories of census v0.1, unchanged.
AI_REPOS = [
    "FlowiseAI/Flowise", "langgenius/dify", "langflow-ai/langflow", "vllm-project/vllm",
    "comfyanonymous/ComfyUI", "open-webui/open-webui", "BerriAI/litellm", "sgl-project/sglang",
    "invoke-ai/InvokeAI", "oobabooga/text-generation-webui", "mudler/LocalAI",
    "infiniflow/ragflow", "Mintplex-Labs/anything-llm", "danny-avila/LibreChat",
    "h2oai/h2ogpt", "mlflow/mlflow", "ray-project/ray", "gradio-app/gradio",
    "run-llama/llama_index", "langchain-ai/langchain", "mem0ai/mem0", "zylon-ai/private-gpt",
    "deepset-ai/haystack", "microsoft/autogen", "crewAIInc/crewAI", "xorbitsai/inference",
    "huggingface/transformers", "feast-dev/feast", "bentoml/BentoML", "zenml-io/zenml",
]

# 15 self-hosted apps + 15 libraries/frameworks whose core purpose is not AI/ML.
CONTROL_REPOS = [
    "mastodon/mastodon", "discourse/discourse", "go-gitea/gitea", "TryGhost/Ghost",
    "directus/directus", "strapi/strapi", "nocodb/nocodb", "louislam/uptime-kuma",
    "jellyfin/jellyfin", "home-assistant/core", "filebrowser/filebrowser", "zulip/zulip",
    "outline/outline", "metabase/metabase", "grafana/grafana",
    "vercel/next.js", "vitejs/vite", "sveltejs/kit", "nuxt/nuxt", "expressjs/express",
    "aio-libs/aiohttp", "urllib3/urllib3", "pallets/werkzeug", "pallets/jinja",
    "encode/starlette", "tornadoweb/tornado", "wagtail/wagtail", "traefik/traefik",
    "caddyserver/caddy", "rails/rails",
]

GROUPS = (("ai", AI_REPOS), ("control", CONTROL_REPOS))

# GitHub advisory ecosystem -> OSV ecosystem.
OSV_ECOSYSTEM = {
    "pip": "PyPI", "npm": "npm", "go": "Go", "maven": "Maven",
    "rubygems": "RubyGems", "rust": "crates.io", "composer": "Packagist",
    "nuget": "NuGet", "pub": "Pub", "erlang": "Hex", "swift": "SwiftURL",
}
CLASSES = ("scanner_visible", "package_not_in_osv", "no_package")
BLIND = ("package_not_in_osv", "no_package")
PERIODS = ("before_2026_05", "from_2026_05")
PERIOD_SPLIT = "2026-05-01"
MIN_AGE_DAYS = 14
# A GitHub-reviewed advisory OSV must return, by ID and by package query.
CANARY = ("GHSA-39mp-8hj3-5c49", "pip", "gradio")
PERM_SEED = 20261015


# ---------------------------------------------------------------- network

def rate_limit_wait(headers, now):
    """Seconds to wait before retrying a 403/429, or None if it is not a rate limit."""
    if not headers:
        return None
    if headers.get("X-RateLimit-Remaining") == "0":
        try:
            reset = int(headers.get("X-RateLimit-Reset") or 0)
        except ValueError:
            return 60
        return max(0, reset - int(now)) + 3
    retry_after = headers.get("Retry-After")
    if retry_after and str(retry_after).isdigit():
        return int(retry_after)
    return None


def next_link(link_header):
    for part in (link_header or "").split(","):
        seg = part.split(";")
        if len(seg) >= 2 and 'rel="next"' in seg[1]:
            return seg[0].strip().strip("<>")
    return None


class Net:
    """HTTP JSON with retries and GitHub rate-limit waits; counts requests."""

    def __init__(self, pace=0.2, max_wait=3700, sleep=time.sleep,
                 opener=urllib.request.urlopen):
        self.pace, self.max_wait, self.sleep, self.opener = pace, max_wait, sleep, opener
        self.counts = {"github": 0, "osv": 0}

    def request(self, url, data=None, accept="application/json"):
        """Return (status, obj, headers); 404 -> (404, None, headers).
        Raises RuntimeError on any other failure after retries."""
        hdrs = {"User-Agent": UA, "Accept": accept}
        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        last = None
        for attempt in range(6):
            self.counts["github" if url.startswith(GITHUB) else "osv"] += 1
            req = urllib.request.Request(url, data=body, headers=hdrs)
            try:
                with self.opener(req, timeout=60) as resp:
                    raw = resp.read().decode("utf-8")
                    status, headers = resp.status, resp.headers
                self.sleep(self.pace)
                return status, (json.loads(raw) if raw.strip() else None), headers
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    return 404, None, e.headers
                if e.code in (403, 429):
                    wait = rate_limit_wait(e.headers, time.time())
                    if wait is not None:
                        if wait > self.max_wait:
                            raise RuntimeError("rate limited for %ds: %s" % (wait, url)) from None
                        print("rate limited; waiting %ds" % wait, flush=True)
                        self.sleep(wait)
                        continue
                last = e
                if e.code not in (429, 500, 502, 503, 504):
                    break
            except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
                last = e
            self.sleep(min(60, 5 * (attempt + 1)))
        raise RuntimeError("request failed: %s (%s)" % (url, last))


def list_advisories(net, repo):
    """(published repository advisories, status) for one GitHub repo."""
    url = "%s/repos/%s/security-advisories?state=published&per_page=100" % (GITHUB, repo)
    out = []
    while url:
        status, page, headers = net.request(url, accept="application/vnd.github+json")
        if status == 404:
            return out, "not_found"
        if not isinstance(page, list):
            return out, "unexpected_response"
        out.extend(page)
        url = next_link(headers.get("Link", "") if headers else "")
    return out, "ok"


def osv_record(net, vuln_id):
    if not vuln_id:
        return None
    status, obj, _ = net.request("%s/v1/vulns/%s" % (OSV, urllib.parse.quote(vuln_id)))
    return obj if status == 200 and isinstance(obj, dict) and obj.get("id") else None


def osv_package_ids(net, eco, name):
    """Every vulnerability ID and alias OSV lists for a package (any version)."""
    query = {"package": {"name": name, "ecosystem": OSV_ECOSYSTEM[eco]}}
    ids = set()
    while True:
        _, obj, _ = net.request(OSV + "/v1/query", data=query)
        for v in (obj or {}).get("vulns") or []:
            ids.add(v.get("id"))
            ids.update(v.get("aliases") or [])
        token = (obj or {}).get("next_page_token")
        if not token:
            return ids
        query = dict(query, page_token=token)


# ---------------------------------------------------------------- classify

def normalize_name(eco, name):
    name = (name or "").strip()
    if eco == "pip":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco in ("npm", "rubygems", "rust", "composer", "nuget", "pub", "erlang"):
        return name.lower()
    return name


def advisory_packages(adv):
    """[(ecosystem, name)] an advisory names, limited to ecosystems OSV knows."""
    out = []
    for v in adv.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        eco = (pkg.get("ecosystem") or "").lower()
        name = (pkg.get("name") or "").strip()
        if eco in OSV_ECOSYSTEM and name and (eco, name) not in out:
            out.append((eco, name))
    return out


def record_names_package(record, pkgs):
    """True if an OSV record's affected list includes one of the named packages."""
    wanted = {(OSV_ECOSYSTEM[e], normalize_name(e, n)) for e, n in pkgs}
    back = {v: k for k, v in OSV_ECOSYSTEM.items()}
    for a in (record or {}).get("affected") or []:
        p = a.get("package") or {}
        osv_eco = p.get("ecosystem") or ""
        gh_eco = back.get(osv_eco, "")
        if (osv_eco, normalize_name(gh_eco, p.get("name"))) in wanted:
            return True
    return False


def classify(adv, own_record, package_ids):
    """(scanner_class, packages). package_ids(eco, name) -> set of OSV IDs+aliases."""
    pkgs = advisory_packages(adv)
    if not pkgs:
        return "no_package", pkgs
    if own_record is not None and record_names_package(own_record, pkgs):
        return "scanner_visible", pkgs
    ghsa, cve = adv.get("ghsa_id"), adv.get("cve_id")
    for eco, name in pkgs:
        seen = package_ids(eco, name)
        if ghsa in seen or (cve and cve in seen):
            return "scanner_visible", pkgs
    return "package_not_in_osv", pkgs


def parse_time(text):
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def period(published):
    if not published:
        return ""
    return PERIODS[0] if published[:10] < PERIOD_SPLIT else PERIODS[1]


def build_row(group, repo, adv, own_record, cls, pkgs, snapshot):
    published = adv.get("published_at") or ""
    when = parse_time(published)
    age = (snapshot - when).total_seconds() / 86400 if when else None
    return {
        "group": group, "repo": repo, "ghsa_id": adv.get("ghsa_id") or "",
        "cve_id": adv.get("cve_id") or "", "severity": adv.get("severity") or "",
        "published_at": published, "age_days": "" if age is None else round(age, 1),
        "period": period(published), "own_id_in_osv": own_record is not None,
        "scanner_class": cls, "packages": ";".join("%s:%s" % p for p in pkgs),
        "url": adv.get("html_url") or "",
    }


# ---------------------------------------------------------------- summarize

def is_blind(r):
    return r["scanner_class"] in BLIND


def not_own(r):
    return not r["own_id_in_osv"]


def eligible(rows):
    """Measured rows published at least MIN_AGE_DAYS before the snapshot."""
    return [r for r in rows if r["scanner_class"] in CLASSES and r["age_days"] != ""
            and float(r["age_days"]) >= MIN_AGE_DAYS]


def wilson(k, n, z=1.96):
    if not n:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - h) / d, 4), round((c + h) / d, 4)]


def share(rows, pred):
    n = len(rows)
    k = sum(1 for r in rows if pred(r))
    return {"k": k, "n": n, "pct": round(100.0 * k / n, 1) if n else None,
            "ci95": wilson(k, n)}


def median(values):
    v = sorted(values)
    if not v:
        return None
    mid = len(v) // 2
    return v[mid] if len(v) % 2 else (v[mid - 1] + v[mid]) / 2


def group_summary(rows):
    elig = eligible(rows)
    per_repo = {}
    for r in elig:
        per_repo.setdefault(r["repo"], []).append(r)
    repo_blind = {k: sum(map(is_blind, v)) / len(v) for k, v in per_repo.items()}
    sev = {}
    for r in elig:
        if is_blind(r):
            key = r["severity"] or "unknown"
            sev[key] = sev.get(key, 0) + 1
    return {
        "advisories": len(rows),
        "eligible": len(elig),
        "repos_with_eligible_advisories": len(per_repo),
        "scanner_blind": share(elig, is_blind),
        "own_id_not_in_osv": share(elig, not_own),
        "classes": {c: sum(1 for r in elig if r["scanner_class"] == c) for c in CLASSES},
        "by_period": {p: {"scanner_blind": share([r for r in elig if r["period"] == p], is_blind),
                          "own_id_not_in_osv": share([r for r in elig if r["period"] == p], not_own)}
                      for p in PERIODS},
        "repo_median_blind_pct": (None if not repo_blind
                                  else round(100 * median(repo_blind.values()), 1)),
        "repos_all_blind": sorted(k for k, v in repo_blind.items() if v == 1.0),
        "repos_none_blind": sorted(k for k, v in repo_blind.items() if v == 0.0),
        "blind_by_severity": sev,
        "per_repo": {k: {"eligible": len(v), "blind": sum(map(is_blind, v)),
                         "own_id_not_in_osv": sum(map(not_own, v))}
                     for k, v in sorted(per_repo.items())},
    }


def permutation_test(rows, pred, n_perm=10000, seed=PERM_SEED, groups=("ai", "control")):
    """Two-sided test of (pooled share in groups[0]) - (pooled share in groups[1]),
    shuffling group labels across repositories, not advisories."""
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


def summarize(rows, n_perm=10000):
    elig = eligible(rows)
    out = {"groups": {g: group_summary([r for r in rows if r["group"] == g]) for g, _ in GROUPS},
           "comparison": {"scanner_blind": permutation_test(elig, is_blind, n_perm),
                          "own_id_not_in_osv": permutation_test(elig, not_own, n_perm)},
           "comparison_by_period": {}}
    for p in PERIODS:
        sub = [r for r in elig if r["period"] == p]
        out["comparison_by_period"][p] = {
            "scanner_blind": permutation_test(sub, is_blind, n_perm),
            "own_id_not_in_osv": permutation_test(sub, not_own, n_perm)}
    return out


def render(summary):
    lines = ["Advisory-import gap: ai vs control (snapshot %s)" % summary["snapshot_utc"],
             "Eligible = published >= %d days before the snapshot." % MIN_AGE_DAYS]
    for g, _ in GROUPS:
        s = summary["groups"][g]
        b, o = s["scanner_blind"], s["own_id_not_in_osv"]
        lines.append("  %-8s eligible %4d in %2d repos | scanner-blind %s%% %s | own ID not in OSV %s%% %s"
                     % (g, s["eligible"], s["repos_with_eligible_advisories"],
                        b["pct"], b["ci95"], o["pct"], o["ci95"]))
    for key in ("scanner_blind", "own_id_not_in_osv"):
        c = summary["comparison"][key]
        if c:
            lines.append("  %s: ai - control = %+.1f points, permutation p = %s (%d repos)"
                         % (key, c["difference_pct_points"], c["p_two_sided"], c["repositories"]))
    return "\n".join(lines)


# ---------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out-dir", default="out")
    ap.add_argument("--pace", type=float, default=0.2, help="seconds between requests")
    ap.add_argument("--permutations", type=int, default=10000)
    ap.add_argument("--limit-repos", type=int, default=0, help="first N repos per group (smoke test)")
    args = ap.parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)
    snapshot = datetime.now(timezone.utc)
    net = Net(pace=args.pace)

    ghsa, eco, name = CANARY
    if osv_record(net, ghsa) is None:
        print("SELF-CHECK FAILED: OSV did not return %s by ID; not measuring." % ghsa, flush=True)
        return 2
    try:
        package_query = ghsa in osv_package_ids(net, eco, name)
    except RuntimeError as e:
        print("package query failed (%s)" % e, flush=True)
        package_query = False
    print("self-check: OSV by ID ok; package query %s" % ("ok" if package_query else
          "NOT usable, falling back to own-record visibility"), flush=True)

    cache = {}

    def package_ids(e, n):
        if not package_query:
            return set()
        key = (e, normalize_name(e, n))
        if key not in cache:
            cache[key] = osv_package_ids(net, e, n)
        return cache[key]

    rows, repos = [], {}
    for group, names in GROUPS:
        for repo in names[:args.limit_repos or None]:
            try:
                advs, status = list_advisories(net, repo)
            except RuntimeError as e:
                advs, status = [], "error: %s" % e
            repos[repo] = {"group": group, "status": status, "advisories": len(advs)}
            print("%-8s %-36s %-10s %d advisories" % (group, repo, status[:10], len(advs)), flush=True)
            for adv in advs:
                try:
                    own = osv_record(net, adv.get("ghsa_id"))
                    cls, pkgs = classify(adv, own, package_ids)
                except RuntimeError as e:
                    print("  %s: %s" % (adv.get("ghsa_id"), e), flush=True)
                    own, cls, pkgs = None, "error", []
                rows.append(build_row(group, repo, adv, own, cls, pkgs, snapshot))

    summary = {"snapshot_utc": snapshot.isoformat(timespec="seconds"),
               "package_query": package_query, "canary": ghsa,
               "min_age_days": MIN_AGE_DAYS, "period_split": PERIOD_SPLIT,
               "rows": len(rows), "errors": sum(1 for r in rows if r["scanner_class"] == "error"),
               "repos": repos}
    summary.update(summarize(rows, args.permutations))
    summary["requests"] = dict(net.counts, osv_packages_queried=len(cache))

    fields = ["group", "repo", "ghsa_id", "cve_id", "severity", "published_at", "age_days",
              "period", "own_id_in_osv", "scanner_class", "packages", "url"]
    with open(os.path.join(args.out_dir, "group_census.csv"), "w", newline="",
              encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(args.out_dir, "summary_groups.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
    print(render(summary), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
