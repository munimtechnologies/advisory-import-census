"""CVE-reuse check: are a repository's missing advisories blocked by an existing global advisory?

Question (github/advisory-database#10746): a project published repository security advisories
that name an npm package, yet `GET /advisories/{ghsa_id}` still returns 404 days later. If an
advisory reuses a CVE ID that already has a reviewed advisory in the global GitHub Advisory
Database (for example, a fork re-publishing its upstream's CVEs), the curators would have to
merge it into that existing advisory rather than import a second one for the same CVE.

For every published repository advisory of --repo this records:
  - whether its own GHSA is in the global database (200 / 404),
  - whether OSV has a record for it,
  - for a CVE ID: every global advisory already carrying that CVE, with its packages,
and classifies it as in_global / missing_no_cve / missing_cve_already_in_global /
missing_cve_unclaimed.

Unauthenticated public APIs only (about 2 GitHub calls per advisory; 60 calls/hour limit, so
the script waits for the reset when it runs out). Stdlib only. Apache-2.0.
Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import datetime as dt
import json
import os
import re
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
OSV = "https://api.osv.dev/v1/vulns/"
UA = "advisory-import-census-cve-reuse/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"


def next_link(link_header):
    """Return the rel="next" URL from a GitHub Link header, or None."""
    for part in (link_header or "").split(","):
        m = re.search(r'<([^>]+)>\s*;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


def packages_of(advisory):
    """Set of 'ecosystem:name' for a global or repository advisory JSON object."""
    out = set()
    for v in advisory.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        if pkg.get("name"):
            out.add("%s:%s" % (pkg.get("ecosystem") or "", pkg["name"]))
    return out


def classify(own_ghsa, cve_id, global_status, cve_matches, own_packages):
    """Classify one repository advisory.

    cve_matches: list of global advisory JSON objects returned for cve_id (may include own).
    Returns (category, other_ghsas, own_package_already_listed).
    """
    others = [a for a in cve_matches if a.get("ghsa_id") != own_ghsa]
    other_ids = sorted(a.get("ghsa_id") for a in others)
    listed = any(packages_of(a) & own_packages for a in others)
    if global_status == 200:
        return "in_global", other_ids, listed
    if not cve_id:
        return "missing_no_cve", other_ids, listed
    if others:
        return "missing_cve_already_in_global", other_ids, listed
    return "missing_cve_unclaimed", other_ids, listed


def summarize(rows):
    counts = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    return dict(sorted(counts.items()))


class Client:
    def __init__(self, sleep=time.sleep, max_wait=3900):
        self.calls = 0
        self.sleep = sleep
        self.max_wait = max_wait

    def get(self, url):
        """GET url; return (status, headers, parsed JSON or None). Waits once on a rate limit."""
        for attempt in range(2):
            req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                       "Accept": "application/vnd.github+json"})
            self.calls += 1
            try:
                # Headers stay an HTTPMessage: its .get() ignores case (GitHub sends lower case).
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return resp.status, resp.headers, json.loads(resp.read() or b"null")
            except urllib.error.HTTPError as e:
                hdrs = e.headers or {}
                if e.code in (403, 429) and hdrs.get("X-RateLimit-Remaining") == "0" and attempt == 0:
                    reset = int(hdrs.get("X-RateLimit-Reset", "0"))
                    wait = min(max(reset - int(time.time()) + 5, 5), self.max_wait)
                    print("rate limited; waiting %ds" % wait, flush=True)
                    self.sleep(wait)
                    continue
                return e.code, hdrs, None
        return 0, {}, None


def run(repo, out_dir, client):
    advisories = []
    url = "%s/repos/%s/security-advisories?state=published&per_page=100" % (API, repo)
    while url:
        status, hdrs, body = client.get(url)
        if status != 200:
            raise SystemExit("listing %s failed: HTTP %s" % (repo, status))
        advisories.extend(body)
        url = next_link(hdrs.get("Link"))

    rows = []
    for adv in sorted(advisories, key=lambda a: a.get("published_at") or ""):
        ghsa, cve = adv["ghsa_id"], adv.get("cve_id")
        own_pkgs = packages_of(adv)
        gstatus, _, _ = client.get("%s/advisories/%s" % (API, ghsa))
        matches = []
        if cve:
            s, _, body = client.get("%s/advisories?cve_id=%s" % (API, cve))
            if s == 200 and isinstance(body, list):
                matches = body
        try:
            with urllib.request.urlopen(urllib.request.Request(
                    OSV + ghsa, headers={"User-Agent": UA}), timeout=60) as r:
                osv = r.status
        except urllib.error.HTTPError as e:
            osv = e.code
        category, others, listed = classify(ghsa, cve, gstatus, matches, own_pkgs)
        rows.append({
            "ghsa_id": ghsa, "cve_id": cve, "repo_published_at": adv.get("published_at"),
            "severity": adv.get("severity"), "packages": sorted(own_pkgs),
            "global_status": gstatus, "osv_status": osv, "category": category,
            "other_global_ghsas": others,
            "other_global_detail": [
                {"ghsa_id": a.get("ghsa_id"), "type": a.get("type"),
                 "source_code_location": a.get("source_code_location"),
                 "published_at": a.get("published_at"), "packages": sorted(packages_of(a))}
                for a in matches if a.get("ghsa_id") != ghsa],
            "own_package_already_listed": listed,
        })

    result = {
        "repo": repo,
        "checked_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "advisories": len(rows), "counts": summarize(rows), "github_calls": client.calls,
        "rows": rows,
    }
    os.makedirs(out_dir, exist_ok=True)
    slug = repo.replace("/", "__")
    with open(os.path.join(out_dir, slug + ".json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    lines = ["# CVE reuse check: %s (%s)" % (repo, result["checked_at"]), "",
             "Counts: " + ", ".join("%s %d" % kv for kv in result["counts"].items()), "",
             "| GHSA | CVE | repo published | global | OSV | category | existing global GHSA (packages) |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        det = "; ".join("%s (%s)" % (d["ghsa_id"], ", ".join(d["packages"]))
                        for d in r["other_global_detail"])
        lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            r["ghsa_id"], r["cve_id"] or "-", (r["repo_published_at"] or "")[:10],
            r["global_status"], r["osv_status"], r["category"], det or "-"))
    with open(os.path.join(out_dir, slug + ".md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(json.dumps({k: result[k] for k in ("repo", "checked_at", "advisories", "counts",
                                             "github_calls")}, indent=1))
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", action="append", required=True, help="owner/name (repeatable)")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    client = Client()
    for repo in args.repo:
        run(repo, args.out_dir, client)


if __name__ == "__main__":
    main()
