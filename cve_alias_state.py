#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made with AI agents working for MV2 of Munim, Inc.
"""cve_alias_state: tell apart CVE IDs that have no CVE record.

A CVE ID cited by an advisory can be missing from the CVE List for three different reasons: it is RESERVED
(allocated to a CNA but never published), it was REJECTED before it ever got a record, or it was never
allocated at all. The record endpoint (/api/cve/<id>) answers CVE_RECORD_DNE for all of them. The public
CVE Services ID endpoint (/api/cve-id/<id>, no account needed) tells them apart.

Usage:
  python cve_alias_state.py CVE-2013-3364 CVE-2016-1000249
  python cve_alias_state.py --from-file ids.txt --json
  python cve_alias_state.py --advisory-dir path/to/advisory-database/advisories/github-reviewed
  python cve_alias_state.py ... --fail-on REJECTED,NOT_FOUND     (exit 1 if any ID has one of these states)

Output: one CSV row (or JSON object) per distinct CVE ID: cve, state, owning_cna, sources.
States: PUBLISHED, RESERVED, REJECTED, NOT_FOUND (HTTP 404: never allocated), ERROR, INVALID (not a CVE ID).
Note: CVE Services shows the owning CNA of a RESERVED ID as "[REDACTED]" to anonymous readers.
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

API = "https://cveawg.mitre.org/api/cve-id/"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
STATES = ("PUBLISHED", "RESERVED", "REJECTED", "NOT_FOUND", "ERROR", "INVALID")
USER_AGENT = "cve-alias-state/0.1 (+https://github.com/munimtechnologies/advisory-import-census)"


def normalize(cve_id):
    """Return the ID upper-cased and stripped, or None if it is not a well-formed CVE ID."""
    if not isinstance(cve_id, str):
        return None
    s = cve_id.strip().upper()
    return s if CVE_RE.match(s) else None


def classify(status, body):
    """Map an HTTP status and parsed JSON body (or None) from /api/cve-id/ to (state, owning_cna)."""
    if status == 404:
        return "NOT_FOUND", ""
    if status == 200 and isinstance(body, dict):
        state = str(body.get("state", "")).upper()
        if state in ("PUBLISHED", "RESERVED", "REJECTED"):
            return state, str(body.get("owning_cna", "") or "")
    return "ERROR", ""


def _http_get(url, timeout=30):
    """Return (status, parsed JSON or None). Network errors raise OSError."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        return e.code, None
    try:
        return status, json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return status, None


def lookup(cve_id, getter=_http_get, tries=3, pause=0.4, sleep=time.sleep):
    """Return (state, owning_cna) for one ID. Retries on network errors and 5xx/429."""
    norm = normalize(cve_id)
    if norm is None:
        return "INVALID", ""
    for attempt in range(tries):
        try:
            status, body = getter(API + norm)
        except OSError:
            status, body = None, None
        if status is not None and status not in (429,) and not (500 <= status < 600):
            return classify(status, body)
        if attempt + 1 < tries:
            sleep(pause * (attempt + 1) * 2)
    return "ERROR", ""


def aliases_from_osv(doc):
    """CVE IDs listed in an OSV-format advisory's aliases (GitHub advisory-database JSON files use OSV)."""
    out = []
    if isinstance(doc, dict):
        for a in doc.get("aliases") or []:
            n = normalize(a)
            if n:
                out.append(n)
    return out


def collect_from_dir(root):
    """Walk a folder of OSV JSON advisories; return {cve: [advisory ids]} for live (not withdrawn) ones."""
    found = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                    doc = json.load(fh)
            except (OSError, ValueError):
                continue
            if not isinstance(doc, dict) or doc.get("withdrawn"):
                continue
            adv = str(doc.get("id", name[:-5]))
            for cve in aliases_from_osv(doc):
                found.setdefault(cve, []).append(adv)
    return found


def run(ids_to_sources, getter=_http_get, pause=0.4, sleep=time.sleep):
    """Look up every distinct ID; return a list of row dicts sorted by CVE ID."""
    rows = []
    for i, cve in enumerate(sorted(ids_to_sources)):
        if i:
            sleep(pause)
        state, cna = lookup(cve, getter=getter, pause=pause, sleep=sleep)
        rows.append({"cve": cve, "state": state, "owning_cna": cna,
                     "sources": " ".join(ids_to_sources[cve])})
    return rows


def main(argv=None, getter=_http_get, out=sys.stdout, sleep=time.sleep):
    p = argparse.ArgumentParser(description="Read the CVE Services state of CVE IDs (Apache-2.0).")
    p.add_argument("ids", nargs="*", help="CVE IDs")
    p.add_argument("--from-file", help="text file with one CVE ID per line (# comments allowed)")
    p.add_argument("--advisory-dir", help="folder of OSV-format JSON advisories; reads their CVE aliases")
    p.add_argument("--json", action="store_true", help="print JSON instead of CSV")
    p.add_argument("--fail-on", default="", help="comma-separated states; exit 1 if any ID has one")
    p.add_argument("--pause", type=float, default=0.4, help="seconds between requests (default 0.4)")
    a = p.parse_args(argv)

    sources = {}
    for raw in a.ids:
        sources.setdefault(normalize(raw) or raw.strip(), []).append("arg")
    if a.from_file:
        with open(a.from_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    sources.setdefault(normalize(line) or line, []).append("file")
    if a.advisory_dir:
        for cve, advs in collect_from_dir(a.advisory_dir).items():
            sources.setdefault(cve, []).extend(advs)
    if not sources:
        p.error("give CVE IDs, --from-file or --advisory-dir")

    fail_on = {s.strip().upper() for s in a.fail_on.split(",") if s.strip()}
    unknown = fail_on - set(STATES)
    if unknown:
        p.error("unknown state(s) in --fail-on: " + ", ".join(sorted(unknown)))

    rows = run(sources, getter=getter, pause=a.pause, sleep=sleep)
    if a.json:
        out.write(json.dumps(rows, indent=1) + "\n")
    else:
        w = csv.DictWriter(out, fieldnames=["cve", "state", "owning_cna", "sources"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    return 1 if any(r["state"] in fail_on for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
