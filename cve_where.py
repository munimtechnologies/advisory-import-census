#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made with AI agents working for MV2 of Munim, Inc.
"""cve_where: where one CVE stands in CVE.org, NVD, GitHub's Advisory Database and OSV, and why a CVE lookup in
GitHub's Advisory Database may find nothing.

For each CVE ID it makes the same public, no-account calls that people otherwise make by hand when they open an
issue like "GitHub issued this CVE but I can't find it in the Advisory Database":

  1. CVE Services ID state         https://cveawg.mitre.org/api/cve-id/<CVE>   (PUBLISHED / RESERVED / REJECTED / 404)
  2. CVE record                    https://cveawg.mitre.org/api/cve/<CVE>      (assigner, date, cited references)
  3. NVD                           services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>
  4. GitHub lookup by CVE          https://api.github.com/advisories?cve_id=<CVE>
  5. each cited GitHub repository advisory (github.com/<owner>/<repo>/security/advisories/GHSA-...):
       its state and package ecosystems   /repos/<owner>/<repo>/security-advisories/<GHSA>
       and whether it is a global advisory /advisories/<GHSA>
  6. OSV                           https://api.osv.dev/v1/vulns/<CVE>

and prints what each source says plus plain findings ("Why"). The findings only restate what the sources returned;
they are not a judgement on any advisory.

Usage:
  python cve_where.py CVE-2026-49481
  python cve_where.py CVE-2026-49481 CVE-2026-56671 --json
  python cve_where.py --from-file ids.txt --fail-if-missing    (exit 1 if any CVE has no live GitHub advisory)

Anonymous GitHub API calls are limited to 60 an hour; each CVE takes 1 + 2 per cited repository advisory. If the
GITHUB_TOKEN environment variable is set, it is sent to api.github.com only. By default the tool waits for the
GitHub rate-limit reset instead of failing (--no-wait to fail fast). NVD calls are spaced 6.5 s apart (NVD's
public limit is 5 requests per 30 s without a key).

Python 3.9+, standard library only. Apache-2.0.
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

CVE_ID_API = "https://cveawg.mitre.org/api/cve-id/%s"
CVE_REC_API = "https://cveawg.mitre.org/api/cve/%s"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
GH_BY_CVE = "https://api.github.com/advisories?cve_id=%s"
GH_GLOBAL = "https://api.github.com/advisories/%s"
GH_REPO = "https://api.github.com/repos/%s/%s/security-advisories/%s"
OSV_API = "https://api.osv.dev/v1/vulns/%s"
USER_AGENT = "cve-where/0.1 (+https://github.com/munimtechnologies/advisory-import-census)"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
REPO_ADV_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/security/advisories/"
    r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})", re.IGNORECASE)
# Package ecosystems GitHub reviews advisories for (repository advisory API values); "" and "other" are not.
SUPPORTED = {"rubygems", "npm", "pip", "maven", "nuget", "composer", "go", "rust", "erlang", "actions", "pub",
             "swift"}
MIN_INTERVAL = {"cveawg.mitre.org": 0.4, "services.nvd.nist.gov": 6.5, "api.github.com": 1.0, "api.osv.dev": 0.2}
MAX_REPO_ADVS = 3
GITHUB_CNA_SOURCE = "security-advisories@github.com"


def normalize(cve_id):
    """The ID upper-cased and stripped, or None if it is not a well-formed CVE ID."""
    if not isinstance(cve_id, str):
        return None
    s = cve_id.strip().upper()
    return s if CVE_RE.match(s) else None


def norm_ghsa(g):
    parts = str(g or "").split("-")
    if len(parts) != 4:
        return str(g or "")
    return "GHSA-" + "-".join(p.lower() for p in parts[1:])


# ---------- HTTP ----------

def http_get(url, timeout=30):
    """(status, parsed JSON or None, lower-case headers). Network errors raise OSError."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if url.startswith("https://api.github.com/"):
        headers["Accept"] = "application/vnd.github+json"
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw, status, hdrs = resp.read(), resp.status, resp.headers
    except urllib.error.HTTPError as e:
        hdrs = e.headers
        return e.code, None, {k.lower(): v for k, v in (hdrs.items() if hdrs is not None else [])}
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        body = None
    return status, body, {k.lower(): v for k, v in hdrs.items()}


class Client:
    """Polite GET: spaces calls per host, retries 5xx and network errors, waits out GitHub's rate limit."""

    def __init__(self, getter=http_get, sleep=time.sleep, clock=time.time, wait_rate_limit=True, max_wait=3700.0,
                 tries=3):
        self.getter, self.sleep, self.clock = getter, sleep, clock
        self.wait_rate_limit, self.max_wait, self.tries = wait_rate_limit, max_wait, tries
        self.last = {}

    def _space(self, host):
        gap = MIN_INTERVAL.get(host, 0.5)
        prev = self.last.get(host)
        if prev is not None:
            wait = prev + gap - self.clock()
            if wait > 0:
                self.sleep(wait)
        self.last[host] = self.clock()
        return gap

    def get(self, url):
        """(status, body). status is an int, or 'RATE_LIMITED' / 'ERROR' when no HTTP answer was usable."""
        host = url.split("/")[2]
        status = None
        for attempt in range(self.tries):
            gap = self._space(host)
            try:
                status, body, hdrs = self.getter(url)
            except OSError:
                status, body, hdrs = None, None, {}
            if status is not None and (200 <= status < 300 or status == 404):
                return status, body
            if (status in (403, 429) and host == "api.github.com"
                    and str((hdrs or {}).get("x-ratelimit-remaining", "")) == "0"):
                if not self.wait_rate_limit:
                    return "RATE_LIMITED", None
                try:
                    reset = float((hdrs or {}).get("x-ratelimit-reset") or 0)
                except ValueError:
                    reset = 0.0
                self.sleep(min(max(reset - self.clock(), 0.0) + 2.0, self.max_wait))
                continue
            if status is not None and status < 500 and status not in (403, 429):
                return status, body
            if attempt + 1 < self.tries:
                self.sleep(max(2.0, gap) * (attempt + 1))
        return (status if status is not None else "ERROR"), None


# ---------- reading the sources ----------

def repo_advs_from_urls(urls):
    """GitHub repository advisories cited in a list of reference URLs, first occurrence first."""
    out, seen = [], set()
    for u in urls:
        m = REPO_ADV_RE.search(u or "")
        if m:
            g = norm_ghsa(m.group(3))
            if g not in seen:
                seen.add(g)
                out.append({"owner": m.group(1), "repo": m.group(2), "ghsa": g})
    return out


def refs_from_record(rec):
    """Repository advisories cited anywhere in a CVE JSON 5 record (CNA container first, then ADP containers)."""
    cont = (rec or {}).get("containers") or {}
    blocks = [cont.get("cna") or {}] + [b for b in (cont.get("adp") or []) if isinstance(b, dict)]
    urls = [r.get("url") or "" for b in blocks for r in (b.get("references") or []) if isinstance(r, dict)]
    return repo_advs_from_urls(urls)


def _err(status):
    return "ERROR:%s" % status


def check(cve, client, osv=True):
    """Everything the six sources say about one well-formed CVE ID, plus findings."""
    r = {"cve": cve}

    st, body = client.get(CVE_ID_API % cve)
    if st == 404:
        r["cve_id_state"], r["owning_cna"] = "NOT_FOUND", ""
    elif st == 200 and isinstance(body, dict) and body.get("state"):
        r["cve_id_state"], r["owning_cna"] = str(body["state"]).upper(), str(body.get("owning_cna") or "")
    else:
        r["cve_id_state"], r["owning_cna"] = _err(st), ""

    rec = {"state": "", "assigner": "", "date_published": ""}
    rec_refs = []
    if r["cve_id_state"] in ("PUBLISHED", "REJECTED") or r["cve_id_state"].startswith("ERROR"):
        st, body = client.get(CVE_REC_API % cve)
        if st == 200 and isinstance(body, dict):
            md = body.get("cveMetadata") or {}
            rec = {"state": str(md.get("state") or ""), "assigner": str(md.get("assignerShortName") or ""),
                   "date_published": str(md.get("datePublished") or "")[:10]}
            rec_refs = refs_from_record(body)
        elif st == 404:
            rec["state"] = "NO_RECORD"
        else:
            rec["state"] = _err(st)
    r["cve_record"] = rec

    nvd = {"status": "", "source": "", "published": ""}
    nvd_refs = []
    st, body = client.get(NVD_API % cve)
    if st == 200 and isinstance(body, dict):
        vulns = body.get("vulnerabilities") or []
        if vulns:
            c = vulns[0].get("cve") or {}
            nvd = {"status": str(c.get("vulnStatus") or ""), "source": str(c.get("sourceIdentifier") or ""),
                   "published": str(c.get("published") or "")[:10]}
            nvd_refs = repo_advs_from_urls([x.get("url") for x in c.get("references") or [] if isinstance(x, dict)])
        else:
            nvd["status"] = "NOT_IN_NVD"
    elif st == 404:
        nvd["status"] = "NOT_IN_NVD"
    else:
        nvd["status"] = _err(st)
    r["nvd"] = nvd

    st, body = client.get(GH_BY_CVE % cve)
    if st == 200 and isinstance(body, list):
        r["github_by_cve"] = [{"ghsa": norm_ghsa(a.get("ghsa_id")), "type": str(a.get("type") or ""),
                               "withdrawn": bool(a.get("withdrawn_at"))} for a in body if isinstance(a, dict)]
        r["github_lookup"] = "FOUND" if r["github_by_cve"] else "EMPTY"
    else:
        r["github_by_cve"], r["github_lookup"] = [], _err(st)

    cited, seen = [], set()
    for ref in rec_refs + nvd_refs:
        if ref["ghsa"] not in seen:
            seen.add(ref["ghsa"])
            cited.append(ref)
    r["repo_advisories_cited"] = len(cited)
    items = []
    for ref in cited[:MAX_REPO_ADVS]:
        item = dict(ref)
        st, adv = client.get(GH_REPO % (ref["owner"], ref["repo"], ref["ghsa"]))
        if st == 200 and isinstance(adv, dict):
            item["repo_state"] = str(adv.get("state") or "")
            item["ecosystems"] = sorted({str((v.get("package") or {}).get("ecosystem") or "").lower()
                                         for v in adv.get("vulnerabilities") or [] if isinstance(v, dict)})
            item["repo_cve"] = str(adv.get("cve_id") or "")
        else:
            item["repo_state"] = "NOT_FOUND" if st == 404 else _err(st)
            item["ecosystems"], item["repo_cve"] = [], ""
        st, g = client.get(GH_GLOBAL % ref["ghsa"])
        if st == 200 and isinstance(g, dict):
            item.update(global_state="GLOBAL", global_type=str(g.get("type") or ""),
                        global_cve=str(g.get("cve_id") or ""), global_withdrawn=bool(g.get("withdrawn_at")))
        else:
            item.update(global_state="NOT_GLOBAL" if st == 404 else _err(st), global_type="", global_cve="",
                        global_withdrawn=False)
        items.append(item)
    r["repo_advisories"] = items

    if osv:
        st, body = client.get(OSV_API % cve)
        if st == 200 and isinstance(body, dict):
            r["osv"] = {"id": str(body.get("id") or ""), "aliases": sorted(body.get("aliases") or []),
                        "related": sorted(body.get("related") or [])}
        elif st == 404:
            r["osv"] = {"id": "", "aliases": [], "related": []}
        else:
            r["osv"] = {"id": _err(st), "aliases": [], "related": []}
    r["findings"] = findings(r)
    r["found_on_github"] = any(not a["withdrawn"] for a in r["github_by_cve"])
    return r


def supported(ecosystems):
    return any(e in SUPPORTED for e in ecosystems)


def findings(r):
    """Plain statements derived only from what the sources returned."""
    cve, out = r["cve"], []
    live = [a for a in r["github_by_cve"] if not a["withdrawn"]]
    gone = [a for a in r["github_by_cve"] if a["withdrawn"]]
    if live:
        out.append("FOUND: GitHub's Advisory Database lists %s on %s." % (
            cve, ", ".join("%s (%s)" % (a["ghsa"], a["type"] or "?") for a in live)))
    elif r["github_lookup"].startswith("ERROR"):
        out.append("UNKNOWN: the GitHub lookup by CVE failed (%s); try again later or set GITHUB_TOKEN."
                   % r["github_lookup"])
    else:
        out.append("NOT FOUND: GET /advisories?cve_id=%s returns no live advisory%s." % (
            cve, " (only withdrawn: %s)" % ", ".join(a["ghsa"] for a in gone) if gone else ""))

    st, rec, nvd = r["cve_id_state"], r["cve_record"], r["nvd"]
    if r["nvd"]["source"] == GITHUB_CNA_SOURCE or rec["assigner"] == "GitHub_M":
        out.append("Issued by GitHub's own CNA (GitHub_M).")
    if st == "RESERVED":
        out.append("The CVE ID is RESERVED: no CVE record has been published for it yet.")
    elif st == "NOT_FOUND":
        out.append("CVE Services has no such ID (HTTP 404): it was never allocated.")
    elif st == "REJECTED":
        out.append("The CVE ID is REJECTED.")
    elif st == "PUBLISHED":
        out.append("CVE.org: published%s%s." % (" by " + rec["assigner"] if rec["assigner"] else "",
                                                 " on " + rec["date_published"] if rec["date_published"] else ""))
    if nvd["status"] == "NOT_IN_NVD" and st == "PUBLISHED":
        out.append("NVD has no entry yet. GitHub builds its unreviewed advisories from the NVD feed, so there is "
                   "nothing for one to be built from until NVD has the CVE.")
    elif nvd["status"] and nvd["status"] != "NOT_IN_NVD" and not nvd["status"].startswith("ERROR"):
        out.append("NVD: %s%s." % (nvd["status"], ", published " + nvd["published"] if nvd["published"] else ""))
    osv = r.get("osv") or {}
    if osv.get("id") and not osv["id"].startswith("ERROR"):
        out.append("OSV: has a record %s%s." % (osv["id"], " (aliases: %s)" % ", ".join(osv["aliases"])
                                                 if osv.get("aliases") else ""))

    if not r["repo_advisories"]:
        out.append("No GitHub repository advisory is cited in the CVE record or the NVD references.")
    for a in r["repo_advisories"]:
        name = "%s (%s/%s)" % (a["ghsa"], a["owner"], a["repo"])
        ecos = ", ".join(e if e else "(empty)" for e in a["ecosystems"]) or "(none listed)"
        if a["global_state"] == "GLOBAL":
            if a["global_withdrawn"]:
                out.append("Cited advisory %s is a global advisory but is withdrawn." % name)
            elif a["global_cve"].upper() != cve:
                out.append("Cited advisory %s is a global %s advisory, but its CVE field is %s, not %s." % (
                    name, a["global_type"] or "?", a["global_cve"] or "empty", cve))
            else:
                out.append("Cited advisory %s is a global %s advisory with this CVE." % (name, a["global_type"] or "?"))
        elif a["global_state"] == "NOT_GLOBAL":
            if a["repo_state"] == "NOT_FOUND":
                out.append("Cited repository advisory %s is not public (HTTP 404) and is not a global advisory."
                           % name)
            elif a["repo_state"].startswith("ERROR"):
                out.append("Cited advisory %s is not a global advisory; its repository advisory could not be read "
                           "(%s)." % (name, a["repo_state"]))
            elif supported(a["ecosystems"]):
                out.append("Cited repository advisory %s (state %s) names a package in a supported registry (%s) "
                           "but is not in the global database." % (name, a["repo_state"] or "?", ecos))
            else:
                out.append("Cited repository advisory %s (state %s) is not in the global database and names no "
                           "package in a supported registry (ecosystem: %s). GitHub reviews advisories for "
                           "packages from supported registries." % (name, a["repo_state"] or "?", ecos))
        else:
            out.append("Cited advisory %s: the global lookup failed (%s)." % (name, a["global_state"]))
    if r["repo_advisories_cited"] > len(r["repo_advisories"]):
        out.append("%d more cited repository advisories were not read." % (
            r["repo_advisories_cited"] - len(r["repo_advisories"])))
    return out


# ---------- output ----------

def render_text(r):
    if r.get("invalid"):
        return "%s\n  not a well-formed CVE ID\n" % r["cve"]
    rec, nvd = r["cve_record"], r["nvd"]
    lines = [r["cve"]]
    cveorg = r["cve_id_state"]
    if rec["state"]:
        cveorg += "; record %s%s%s" % (rec["state"], " by " + rec["assigner"] if rec["assigner"] else "",
                                       " on " + rec["date_published"] if rec["date_published"] else "")
    lines.append("  CVE.org   " + cveorg)
    lines.append("  NVD       " + (nvd["status"] or "?") + (" (source %s, published %s)" % (
        nvd["source"], nvd["published"]) if nvd["source"] else ""))
    gh = ", ".join("%s %s%s" % (a["ghsa"], a["type"], " withdrawn" if a["withdrawn"] else "")
                   for a in r["github_by_cve"]) or r["github_lookup"]
    lines.append("  GitHub    ?cve_id= -> " + gh)
    for a in r["repo_advisories"]:
        lines.append("  Repo adv  %s %s/%s: %s; ecosystems %s; global %s%s" % (
            a["ghsa"], a["owner"], a["repo"], a["repo_state"],
            ",".join(e if e else "(empty)" for e in a["ecosystems"]) or "-", a["global_state"],
            " (%s, cve %s)" % (a["global_type"], a["global_cve"] or "none") if a["global_state"] == "GLOBAL" else ""))
    if "osv" in r:
        o = r["osv"]
        lines.append("  OSV       " + ((o["id"] + (" aliases " + ",".join(o["aliases"]) if o["aliases"] else ""))
                                       if o["id"] else "no record with this ID"))
    lines.append("  Why")
    lines += ["    - " + f for f in r["findings"]]
    return "\n".join(lines) + "\n"


def main(argv=None, client=None, out=sys.stdout):
    p = argparse.ArgumentParser(description="Where does a CVE stand in CVE.org, NVD, GitHub's Advisory Database "
                                            "and OSV? (Apache-2.0)")
    p.add_argument("ids", nargs="*", help="CVE IDs")
    p.add_argument("--from-file", help="text file with one CVE ID per line (# comments allowed)")
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--no-osv", action="store_true", help="skip the OSV lookup")
    p.add_argument("--no-wait", action="store_true", help="fail instead of waiting for GitHub's rate-limit reset")
    p.add_argument("--fail-if-missing", action="store_true",
                   help="exit 1 if any CVE has no live advisory in GitHub's Advisory Database (or is invalid)")
    a = p.parse_args(argv)

    raw = list(a.ids)
    if a.from_file:
        with open(a.from_file, encoding="utf-8") as fh:
            raw += [ln.split("#", 1)[0].strip() for ln in fh]
    raw = [x for x in raw if x and x.strip()]
    if not raw:
        p.error("give CVE IDs or --from-file")
    client = client or Client(wait_rate_limit=not a.no_wait)

    results, seen = [], set()
    for x in raw:
        n = normalize(x)
        key = n or x.strip()
        if key in seen:
            continue
        seen.add(key)
        if n is None:
            results.append({"cve": x.strip(), "invalid": True, "found_on_github": False})
            continue
        results.append(check(n, client, osv=not a.no_osv))
    if a.json:
        out.write(json.dumps(results, indent=1) + "\n")
    else:
        out.write("\n".join(render_text(r) for r in results))
    if a.fail_if_missing and not all(r["found_on_github"] for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
