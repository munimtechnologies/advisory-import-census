#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""cargo_lock_ghsa_gap.py: which advisories for a Cargo.lock will cargo-audit and cargo-deny never report?

Part of the cargo-lock-ghsa-gap agent skill in
https://github.com/munimtechnologies/advisory-import-census (skills/cargo-lock-ghsa-gap/).
Made with AI agents working in MV2's (Munim, Inc.) name.

cargo-audit and cargo-deny read only the RustSec advisory database. GitHub's Advisory Database
also reviews crates.io advisories, and many of them never reach RustSec (study S14: 620 of 1,492,
73.4% of those published in 2026). This script reads a Cargo.lock, asks OSV.dev (which holds both
databases) which advisories affect each crates.io package at its locked version, and sorts them:
  RUSTSEC    a RustSec advisory: cargo-audit / cargo-deny already report it
  GHSA_ONLY  a GitHub-reviewed advisory with no RustSec record (by alias or shared CVE):
             cargo-audit / cargo-deny will NOT report it
  COVERED    a GitHub advisory that a RustSec advisory also covers
  OTHER      any other ID (e.g. MAL- malicious-package records)
Requests (read-only HTTPS, no token, nothing written):
  POST https://api.osv.dev/v1/querybatch   up to 1,000 packages per request
  GET  https://api.osv.dev/v1/vulns/<ID>    once per advisory found (at most 200)
Standard library only. Only crates.io packages are checked; git and path dependencies are skipped.

Third-party text: OSV records are written by outside parties. The script keeps only structured
fields (IDs, severity words, version numbers) that fully match a strict pattern or a fixed list, and
replaces anything else with UNRECOGNIZED. It never prints an advisory's summary or details.
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request

__version__ = "0.1.0"

QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
STUDY = "https://github.com/munimtechnologies/advisory-import-census/blob/main/study/rust-ghsa-only-s14/RESULTS.md"
UNRECOGNIZED = "UNRECOGNIZED"
BATCH = 1000
MAX_PACKAGES = 5000
MAX_LOOKUPS = 200
MAX_LIST = 10
CRATES_IO_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)

# [0-9], not \d: \d also matches non-ASCII digits in Python.
CRATE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
VERSION_RE = re.compile(r"[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z.+-]{1,60})?")
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
GHSA_RE = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")
RUSTSEC_RE = re.compile(r"RUSTSEC-[0-9]{4}-[0-9]{4}")
VULN_ID_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{1,15}(-[A-Za-z0-9]{1,24}){1,5}")
GHSA_IN_TEXT = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")
SEVERITIES = ("LOW", "MODERATE", "HIGH", "CRITICAL")
KV_RE = re.compile(r'^\s*(name|version|source)\s*=\s*"([^"\\]*)"\s*$')

UA = "cargo-lock-ghsa-gap/" + __version__ + " (+https://github.com/munimtechnologies/advisory-import-census)"


def _request(req, timeout):
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.HTTPError as exc:
        return exc.code, None
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None
    try:
        return status, json.loads(body)
    except ValueError:
        return status, None


def http_get_json(url, timeout=30):
    """GET url and return (status, parsed JSON or None). Status 0 means no HTTP answer."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    return _request(req, timeout)


def http_post_json(url, payload, timeout=60):
    """POST payload as JSON and return (status, parsed JSON or None)."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "User-Agent": UA, "Accept": "application/json", "Content-Type": "application/json"})
    return _request(req, timeout)


def parse_cargo_lock(text):
    """Return (packages, skipped): unique (name, version) crates.io pairs, and a count of the rest.

    A small line parser for Cargo.lock's [[package]] tables (lockfile versions 1 to 4), so it also
    runs on Python versions without tomllib.
    """
    blocks, cur = [], None
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            cur = {}
            blocks.append(cur)
            continue
        if s.startswith("["):
            if not s.startswith("[[package]]"):
                cur = None
            continue
        if cur is None:
            continue
        m = KV_RE.match(line)
        if m and m.group(1) not in cur:
            cur[m.group(1)] = m.group(2)
    seen, packages, skipped = set(), [], 0
    for b in blocks:
        name, version, source = b.get("name"), b.get("version"), b.get("source", "")
        ok = (name and version and CRATE_RE.fullmatch(name) and VERSION_RE.fullmatch(version)
              and source.startswith(CRATES_IO_SOURCES))
        if not ok:
            skipped += 1
            continue
        key = (name, version)
        if key not in seen:
            seen.add(key)
            packages.append(key)
    return packages, skipped


def clean_id(raw):
    """A validated vulnerability ID, or None."""
    if not isinstance(raw, str) or len(raw) > 64 or not VULN_ID_RE.fullmatch(raw):
        return None
    head = raw.split("-", 1)[0].upper()
    if head == "GHSA":
        s = "GHSA-" + raw[5:].lower()
        return s if GHSA_RE.fullmatch(s) else None
    if head == "CVE":
        s = raw.upper()
        return s if CVE_RE.fullmatch(s) else None
    if head == "RUSTSEC":
        s = raw.upper()
        return s if RUSTSEC_RE.fullmatch(s) else None
    return raw


def query_osv(packages, post):
    """Return ({(name, version): [ids]}, errors)."""
    found, errors = {}, []
    for start in range(0, len(packages), BATCH):
        chunk = packages[start:start + BATCH]
        payload = {"queries": [{"package": {"ecosystem": "crates.io", "name": n}, "version": v}
                               for n, v in chunk]}
        status, data = post(QUERYBATCH, payload)
        results = data.get("results") if isinstance(data, dict) else None
        if status != 200 or not isinstance(results, list) or len(results) != len(chunk):
            errors.append("OSV querybatch failed for packages %d-%d (HTTP %s)"
                          % (start + 1, start + len(chunk), status))
            continue
        for key, res in zip(chunk, results):
            vulns = res.get("vulns") if isinstance(res, dict) else None
            ids = []
            for v in vulns if isinstance(vulns, list) else []:
                i = clean_id(v.get("id")) if isinstance(v, dict) else None
                if i and i not in ids:
                    ids.append(i)
            if ids:
                found[key] = ids
    return found, errors


def record_facts(rec, name):
    """Only the structured facts this script uses, each validated."""
    facts = {"aliases": [], "severity": None, "fixed": [], "ghsa_refs": [], "withdrawn": False}
    if not isinstance(rec, dict):
        return facts
    facts["withdrawn"] = isinstance(rec.get("withdrawn"), str) and bool(rec.get("withdrawn"))
    for a in rec.get("aliases") or []:
        i = clean_id(a)
        if i and i not in facts["aliases"]:
            facts["aliases"].append(i)
    ds = rec.get("database_specific")
    sev = ds.get("severity") if isinstance(ds, dict) else None
    if isinstance(sev, str):
        facts["severity"] = sev.upper() if sev.upper() in SEVERITIES else UNRECOGNIZED
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") if isinstance(aff, dict) else None
        if not isinstance(pkg, dict) or pkg.get("ecosystem") != "crates.io" or pkg.get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            for ev in (rng.get("events") or []) if isinstance(rng, dict) else []:
                fx = ev.get("fixed") if isinstance(ev, dict) else None
                if isinstance(fx, str) and VERSION_RE.fullmatch(fx) and fx not in facts["fixed"]:
                    facts["fixed"].append(fx)
    for ref in rec.get("references") or []:
        url = ref.get("url") if isinstance(ref, dict) else None
        if isinstance(url, str):
            for g in GHSA_IN_TEXT.findall(url[:500]):
                g = clean_id(g)
                if g and g not in facts["ghsa_refs"]:
                    facts["ghsa_refs"].append(g)
    return facts


def classify(found, get):
    """Return (rows, errors). One row per (package, version, advisory)."""
    cache, errors, lookups = {}, [], 0

    def facts(vid, name):
        nonlocal lookups
        key = (vid, name)
        if key in cache:
            return cache[key]
        if lookups >= MAX_LOOKUPS:
            cache[key] = None
            return None
        lookups += 1
        status, rec = get(OSV_VULN + vid)
        if status != 200 or not isinstance(rec, dict):
            errors.append("could not read %s from OSV.dev (HTTP %s)" % (vid, status))
            cache[key] = None
        else:
            cache[key] = record_facts(rec, name)
        return cache[key]

    rows = []
    for (name, version), ids in sorted(found.items()):
        rs_ids = [i for i in ids if i.startswith("RUSTSEC-")]
        rs_map = {}
        for r in rs_ids:
            f = facts(r, name)
            rs_map[r] = set(f["aliases"]) | set(f["ghsa_refs"]) if f else set()
        for vid in ids:
            row = {"package": name, "version": version, "id": vid, "status": None,
                   "severity": None, "cves": [], "fixed": [], "rustsec": []}
            if vid.startswith("RUSTSEC-"):
                row["status"] = "RUSTSEC"
                f = cache.get((vid, name))
                if f:
                    row["cves"] = [a for a in f["aliases"] if a.startswith("CVE-")][:MAX_LIST]
                    row["fixed"] = f["fixed"][:MAX_LIST]
            elif vid.startswith("GHSA-"):
                f = facts(vid, name)
                if f is None:
                    row["status"] = "UNCHECKED"
                elif f["withdrawn"]:
                    continue
                else:
                    row["severity"] = f["severity"]
                    row["cves"] = [a for a in f["aliases"] if a.startswith("CVE-")][:MAX_LIST]
                    row["fixed"] = f["fixed"][:MAX_LIST]
                    linked = sorted({a for a in f["aliases"] if a.startswith("RUSTSEC-")}
                                    | {r for r, cover in rs_map.items()
                                       if vid in cover or any(c in cover for c in row["cves"])})
                    if linked:
                        row["status"] = "COVERED"
                        row["rustsec"] = linked[:MAX_LIST]
                    else:
                        row["status"] = "GHSA_ONLY"
            else:
                row["status"] = "OTHER"
            rows.append(row)
    if lookups >= MAX_LOOKUPS:
        errors.append("stopped after %d advisory lookups; some GHSA rows are UNCHECKED" % MAX_LOOKUPS)
    return rows, errors


def render(report):
    out = []
    out.append("Checked %d crates.io packages from the lockfile against OSV.dev (%d other entries skipped)."
               % (report["packages_checked"], report["skipped"]))
    gaps = [r for r in report["rows"] if r["status"] == "GHSA_ONLY"]
    rs = sorted({r["id"] for r in report["rows"] if r["status"] == "RUSTSEC"})
    cov = [r for r in report["rows"] if r["status"] == "COVERED"]
    other = [r for r in report["rows"] if r["status"] in ("OTHER", "UNCHECKED")]
    out.append("RustSec advisories (cargo-audit / cargo-deny report these): %d%s"
               % (len(rs), (": " + ", ".join(rs[:MAX_LIST])) if rs else ""))
    out.append("GitHub advisories also covered by RustSec: %d" % len(cov))
    out.append("")
    if gaps:
        out.append("NOT in RustSec, so cargo-audit and cargo-deny will NOT report these (%d):" % len(gaps))
        order = {s: i for i, s in enumerate(("CRITICAL", "HIGH", "MODERATE", "LOW"))}
        for r in sorted(gaps, key=lambda r: (order.get(r["severity"], 9), r["package"], r["id"])):
            fixed = ("fixed in " + " / ".join(r["fixed"])) if r["fixed"] else "no fixed version listed"
            out.append("  %s %s  %s  %s  %s  %s" % (
                r["package"], r["version"], r["id"], r["severity"] or "no severity",
                ",".join(r["cves"]) or "no CVE", fixed))
            out.append("    https://github.com/advisories/%s" % r["id"])
    else:
        out.append("No GitHub-only advisories: RustSec covers every GitHub advisory OSV.dev lists for these versions.")
    if other:
        out.append("")
        out.append("Other or unchecked IDs (%d): %s" % (
            len(other), ", ".join(sorted({r["id"] for r in other})[:MAX_LIST])))
    for e in report["errors"]:
        out.append("WARNING: " + e)
    if report.get("note"):
        out.append(report["note"])
    out.append("")
    out.append("Why this gap exists (study S14): " + STUDY)
    return "\n".join(out)


def run(lock_text, get=http_get_json, post=http_post_json):
    packages, skipped = parse_cargo_lock(lock_text)
    note = None
    if len(packages) > MAX_PACKAGES:
        note = "Checked the first %d of %d packages." % (MAX_PACKAGES, len(packages))
        packages = packages[:MAX_PACKAGES]
    found, errors = query_osv(packages, post)
    rows, errors2 = classify(found, get)
    return {"version": __version__, "packages_checked": len(packages), "skipped": skipped,
            "rows": rows, "errors": errors + errors2, "note": note}


def main(argv=None, get=http_get_json, post=http_post_json):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("lockfile", nargs="?", default="Cargo.lock", help="path to Cargo.lock (default ./Cargo.lock)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--version", action="version", version="cargo_lock_ghsa_gap.py " + __version__)
    args = ap.parse_args(argv)
    try:
        with open(args.lockfile, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        print("Cannot read %s" % args.lockfile, file=sys.stderr)
        return 2
    report = run(text, get, post)
    if args.json:
        print(json.dumps(report, indent=1))
    else:
        print(render(report))
    if report["errors"]:
        return 2
    return 1 if any(r["status"] == "GHSA_ONLY" for r in report["rows"]) else 0


if __name__ == "__main__":
    sys.exit(main())
