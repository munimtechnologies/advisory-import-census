#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made by AI agents working for MV2 of Munim, Inc.
"""S21: pre-releases that a GitHub advisory's "introduced" bound leaves out.

Under SemVer ordering, 0.26.0-beta.1 < 0.26.0. So a crates.io range that starts
at `introduced: 0.26.0` treats every published 0.26.0 pre-release as safe, even
when the vulnerable code was already in it. And when the bound names a version
that was never published (only its pre-releases were), the range can start at
nothing the registry ever served.

For every GitHub advisory (GHSA) in OSV's crates.io export this script lists,
per range:
  * gap_pre: published, non-yanked pre-releases of the bound's version that no
    range of the record covers for that package;
  * bound_unpublished: the bound itself is not a crates.io version;
  * rustsec_covers: of the gap pre-releases, those that a RustSec record linked
    by GHSA or CVE alias marks as affected.
A secondary count looks at the other end: a `fixed` bound at a stable version
whose pre-releases are published (those are counted as affected; correct only
if the fix landed after the last pre-release).
Rows are candidates for hand-checking against the released source, not findings.
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone

UA = "mv2-munim-s21/1.0 (mv2@munimtech.com)"
OSV_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip"
ECO = "crates.io"
_NUM = re.compile(r"^\d+$")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------- versions
def semver_key(v):
    """Sort key for SemVer versions. Unparsable -> None."""
    s = str(v).strip().lstrip("v").split("+", 1)[0]
    core, _, pre = s.partition("-")
    parts = core.split(".")
    if not parts or len(parts) > 3 or not all(_NUM.match(p) for p in parts):
        return None
    nums = tuple(int(p) for p in parts) + (0,) * (3 - len(parts))
    if not pre:
        return (nums, (1,))
    ids = []
    for x in pre.split("."):
        ids.append((0, int(x), "") if _NUM.match(x) else (1, 0, x))
    return (nums, (0, tuple(ids)))


def is_pre(v):
    return "-" in str(v).split("+", 1)[0]


def core_of(v):
    k = semver_key(v)
    return k[0] if k else None


def _lt(a, b):
    return a is not None and b is not None and a < b


def _le(a, b):
    return a is not None and b is not None and a <= b


# ---------------------------------------------------------------- OSV ranges
def range_intervals(rng):
    """(lo_key or None, hi_key or None, hi_inclusive, introduced_str, end_kind, end_str) per interval."""
    if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
        return []
    out, lo, lo_s, open_ = [], None, "0", False
    for ev in rng.get("events", []) or []:
        if "introduced" in ev:
            lo_s = str(ev["introduced"])
            lo = None if lo_s == "0" else semver_key(lo_s)
            open_ = True
        elif open_ and ("fixed" in ev or "last_affected" in ev or "limit" in ev):
            kind = "fixed" if "fixed" in ev else ("last_affected" if "last_affected" in ev else "limit")
            hs = str(ev[kind])
            out.append((lo, semver_key(hs), kind == "last_affected", lo_s, kind, hs))
            open_ = False
    if open_:
        out.append((lo, None, False, lo_s, "", ""))
    return out


def covers(affected, version):
    if str(version) in {str(x) for x in affected.get("versions", []) or []}:
        return True
    k = semver_key(version)
    if k is None:
        return False
    for rng in affected.get("ranges", []) or []:
        for lo, hi, inc, lo_s, _, _ in range_intervals(rng):
            if lo_s != "0" and (lo is None or not _le(lo, k)):
                continue
            if hi is None or (inc and _le(k, hi)) or (not inc and _lt(k, hi)):
                return True
    return False


def same_package(rec, name):
    return [a for a in rec.get("affected", []) or []
            if (a.get("package", {}) or {}).get("ecosystem") == ECO
            and (a.get("package", {}) or {}).get("name") == name]


def analyse(rec, releases, others):
    """releases: list of (version, created datetime or None, yanked).
    others: RustSec OSV records linked to this GHSA. Returns (rows, fixed_side_rows)."""
    rows, fixed_rows = [], []
    live = [v for v, _, y in releases if not y and semver_key(v) is not None]
    published = {v for v, _, _ in releases}
    dbs = rec.get("database_specific", {}) or {}
    seen = set()
    for aff in rec.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") != ECO:
            continue
        name = pkg.get("name", "")
        mine = same_package(rec, name)
        theirs = [(o["id"], a) for o in others for a in same_package(o, name)]
        for rng in aff.get("ranges", []) or []:
            for lo, hi, inc, lo_s, end_kind, end_s in range_intervals(rng):
                if lo_s != "0" and lo is not None and not is_pre(lo_s) and (name, lo_s) not in seen:
                    seen.add((name, lo_s))
                    pres = sorted((v for v in live if is_pre(v) and core_of(v) == lo[0]), key=semver_key)
                    gap = [v for v in pres if not any(covers(a, v) for a in mine)]
                    rs = [v for v in gap if any(covers(a, v) for _, a in theirs)]
                    unpublished = lo_s not in published
                    if gap or unpublished:
                        rows.append({
                            "ghsa": rec["id"], "package": name,
                            "aliases": " ".join(rec.get("aliases", []) or []),
                            "severity": dbs.get("severity", ""),
                            "published": (rec.get("published") or "")[:10],
                            "modified": (rec.get("modified") or "")[:10],
                            "introduced": lo_s, "end_kind": end_kind, "end": end_s,
                            "bound_unpublished": unpublished,
                            "n_gap_pre": len(gap), "gap_pre": " ".join(gap[:8]),
                            "rustsec_ids": " ".join(sorted({i for i, _ in theirs})),
                            "n_rustsec_covers": len(rs), "rustsec_covers": " ".join(rs[:8]),
                            "summary": " ".join(str(rec.get("summary", "")).split())[:140],
                        })
                if end_kind == "fixed" and hi is not None and not is_pre(end_s):
                    pres = [v for v in live if is_pre(v) and core_of(v) == hi[0]
                            and (lo is None or _le(lo, semver_key(v)))]
                    if pres:
                        fixed_rows.append({"ghsa": rec["id"], "package": name, "fixed": end_s,
                                           "n_pre_counted_affected": len(pres),
                                           "fixed_published": end_s in published})
    return rows, fixed_rows


# ---------------------------------------------------------------- registry
def get_json(url, tries=4):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=90) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code in (429, 500, 502, 503, 504) and i + 1 < tries:
                time.sleep(5 * (i + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if i + 1 == tries:
                raise
            time.sleep(5 * (i + 1))
    return None


def crates_releases(name):
    out, url = [], "https://crates.io/api/v1/crates/%s/versions?per_page=100" % urllib.parse.quote(name)
    while url:
        doc = get_json(url)
        time.sleep(1.05)  # crates.io crawler policy: at most 1 request per second
        if not doc:
            break
        for v in doc.get("versions", []) or []:
            out.append((v.get("num", ""), v.get("created_at"), bool(v.get("yanked"))))
        nxt = (doc.get("meta", {}) or {}).get("next_page")
        url = ("https://crates.io/api/v1/crates/%s/versions%s" % (urllib.parse.quote(name), nxt)) if nxt else None
    return out


def fetch(url, dest):
    for i in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=180) as resp, open(dest + ".part", "wb") as f:
                while True:
                    b = resp.read(1 << 20)
                    if not b:
                        break
                    f.write(b)
            os.replace(dest + ".part", dest)
            return dest
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            log("fetch failed", url, e)
            time.sleep(15 * (i + 1))
    raise RuntimeError("could not fetch " + url)


def load_osv(zpath):
    recs = []
    with zipfile.ZipFile(zpath) as zf:
        for n in zf.namelist():
            base = os.path.basename(n)
            if n.endswith(".json") and (base.startswith("GHSA-") or base.startswith("RUSTSEC-")):
                try:
                    recs.append(json.loads(zf.read(n)))
                except ValueError:
                    continue
    return recs


def needs_lookup(rec):
    """Package names with a non-zero introduced or a stable fixed bound."""
    names = set()
    for aff in rec.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") != ECO:
            continue
        for rng in aff.get("ranges", []) or []:
            for lo, hi, _, lo_s, kind, end_s in range_intervals(rng):
                if (lo_s != "0" and not is_pre(lo_s)) or (kind == "fixed" and not is_pre(end_s)):
                    names.add(pkg.get("name", ""))
    return names


def summarize(rows, fixed_rows, n_ghsa, n_ranges_nonzero):
    s = Counter()
    s["ghsa_records"] = n_ghsa
    s["distinct_nonzero_stable_introduced_bounds"] = n_ranges_nonzero
    s["rows"] = len(rows)
    for r in rows:
        if r["n_gap_pre"]:
            s["gap_rows"] += 1
            s["gap_prereleases_total"] += r["n_gap_pre"]
            s["gap_high_or_critical"] += r["severity"] in ("HIGH", "CRITICAL")
            if r["rustsec_ids"]:
                s["gap_with_rustsec"] += 1
                s["gap_rustsec_covers"] += r["n_rustsec_covers"] > 0
        if r["bound_unpublished"]:
            s["bound_unpublished_rows"] += 1
            s["bound_unpublished_with_gap"] += r["n_gap_pre"] > 0
    s["gap_ghsa_records"] = len({r["ghsa"] for r in rows if r["n_gap_pre"]})
    s["gap_packages"] = len({r["package"] for r in rows if r["n_gap_pre"]})
    s["fixed_side_rows"] = len(fixed_rows)
    s["fixed_side_unpublished_fixed"] = sum(1 for r in fixed_rows if not r["fixed_published"])
    return dict(s)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--cap", type=int, default=3000)
    args = ap.parse_args()
    os.makedirs(args.data_dir, exist_ok=True)
    os.makedirs(args.out_dir, exist_ok=True)
    dest = os.path.join(args.data_dir, "s21-osv-crates-io-all.zip")
    fetch(OSV_ZIP, dest)
    recs = load_osv(dest)
    os.remove(dest)
    ghsas = [r for r in recs if r.get("id", "").startswith("GHSA-") and not r.get("withdrawn")]
    rustsec = [r for r in recs if r.get("id", "").startswith("RUSTSEC-") and not r.get("withdrawn")]
    by_alias = defaultdict(list)
    for o in rustsec:
        for a in set(o.get("aliases", []) or []) | {o["id"]}:
            by_alias[a].append(o)
    names = sorted(set().union(*[needs_lookup(r) for r in ghsas]) if ghsas else set())
    log("ghsa", len(ghsas), "rustsec", len(rustsec), "packages to look up", len(names))
    cache, errors = {}, Counter()
    for i, name in enumerate(names[:args.cap]):
        try:
            cache[name] = crates_releases(name)
        except Exception as e:
            errors[type(e).__name__] += 1
        if i % 100 == 0:
            log("registry", i, "/", len(names))
    rows, fixed_rows, bounds = [], [], set()
    for r in ghsas:
        for aff in r.get("affected", []) or []:
            pkg = aff.get("package", {}) or {}
            if pkg.get("ecosystem") != ECO:
                continue
            for rng in aff.get("ranges", []) or []:
                for _, _, _, lo_s, _, _ in range_intervals(rng):
                    if lo_s != "0" and not is_pre(lo_s):
                        bounds.add((r["id"], pkg.get("name"), lo_s))
        others, seen = [], set()
        for k in {r["id"]} | set(r.get("aliases", []) or []):
            for o in by_alias.get(k, []):
                if o["id"] not in seen:
                    seen.add(o["id"])
                    others.append(o)
        # analyse per package so releases of one crate never leak into another
        for nm in sorted(needs_lookup(r)):
            rel = cache.get(nm)
            if rel is None:
                errors["no_registry_data"] += 1
                continue
            sub = dict(r)
            sub["affected"] = same_package(r, nm)
            a, f = analyse(sub, rel, others)
            rows.extend(a)
            fixed_rows.extend(f)
    stats = summarize(rows, fixed_rows, len(ghsas), len(bounds))
    stats["run_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    stats["rustsec_records"] = len(rustsec)
    stats["packages_looked_up"] = min(len(names), args.cap)
    stats["packages_capped"] = max(0, len(names) - args.cap)
    stats["errors"] = dict(errors)
    rows.sort(key=lambda x: (-x["n_gap_pre"], x["package"], x["ghsa"]))
    fields = list(rows[0].keys()) if rows else ["ghsa"]
    with open(os.path.join(args.out_dir, "rows.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(args.out_dir, "fixed_side.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ghsa", "package", "fixed", "n_pre_counted_affected", "fixed_published"])
        w.writeheader()
        w.writerows(fixed_rows)
    with open(os.path.join(args.out_dir, "summary.json"), "w") as f:
        json.dump(stats, f, indent=1)
    print(json.dumps(stats, indent=1))
    if not ghsas:
        raise SystemExit("no GHSA records in the OSV crates.io export (format change?)")


if __name__ == "__main__":
    sys.exit(main())
