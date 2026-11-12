#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc. Made by AI agents working for MV2 of Munim, Inc.
"""S20: GitHub-reviewed advisories whose affected range ends at "last_affected".

A GitHub-reviewed advisory written before a fix exists often says "<= X", where X
is the newest release on the day it was reviewed. In OSV that becomes
`last_affected: X` with no `fixed` event. If the range is never moved, every
release after X is treated as safe, even when it is still vulnerable.

For crates.io and PyPI this script reads OSV's full export, finds every GHSA
range whose upper bound is `last_affected`, lists the registry's releases with
their upload dates, and reports:
  * frozen: X was the newest release on the day the GHSA was published;
  * later_uncovered: releases after X that no range of the record covers;
  * disputed: those later releases that the ecosystem's own database (RustSec
    for crates.io, PyPA/PYSEC for PyPI), linked by GHSA or CVE alias, marks
    as affected.
Rows are candidates for hand-checking, not findings.
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

UA = "mv2-munim-s20/1.0 (mv2@munimtech.com)"
OSV_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
ECOS = ("crates.io", "PyPI")
SECOND_DB = {"crates.io": "RUSTSEC-", "PyPI": "PYSEC-"}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------- versions
_NUM = re.compile(r"^\d+$")


def semver_key(v):
    """Sort key for SemVer-ish versions (crates.io). Unparsable -> sorts first."""
    s = str(v).strip().lstrip("v").split("+", 1)[0]
    core, _, pre = s.partition("-")
    parts = core.split(".")
    if not parts or not all(_NUM.match(p) for p in parts):
        return (0, (), (), s)
    nums = tuple(int(p) for p in parts) + (0,) * max(0, 3 - len(parts))
    if not pre:
        return (1, nums, (1,), "")
    ids = []
    for x in pre.split("."):
        ids.append((0, int(x), "") if _NUM.match(x) else (1, 0, x))
    return (1, nums, (0, tuple(ids)), "")


def semver_is_pre(v):
    return "-" in str(v).split("+", 1)[0]


def pep440_key(v):
    try:
        from packaging.version import Version, InvalidVersion
    except ImportError:  # pragma: no cover
        return semver_key(v)
    try:
        return (1, Version(str(v)))
    except InvalidVersion:
        return None


def pep440_is_pre(v):
    try:
        from packaging.version import Version
        x = Version(str(v))
        return x.is_prerelease or x.is_devrelease
    except Exception:
        return False


def vkey(eco, v):
    if eco == "PyPI":
        return pep440_key(v)
    return semver_key(v)


def is_pre(eco, v):
    return pep440_is_pre(v) if eco == "PyPI" else semver_is_pre(v)


def norm_name(eco, name):
    if eco == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


# ---------------------------------------------------------------- OSV ranges
def range_intervals(eco, rng):
    """Return a list of (lo_key or None, hi_key or None, hi_inclusive) for one OSV range."""
    if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
        return []
    out, lo = [], None
    open_ = False
    for ev in rng.get("events", []) or []:
        if "introduced" in ev:
            iv = ev["introduced"]
            lo = None if iv in ("0", 0) else vkey(eco, iv)
            open_ = True
        elif "fixed" in ev and open_:
            out.append((lo, vkey(eco, ev["fixed"]), False))
            open_ = False
        elif "last_affected" in ev and open_:
            out.append((lo, vkey(eco, ev["last_affected"]), True))
            open_ = False
        elif "limit" in ev and open_:
            out.append((lo, vkey(eco, ev["limit"]), False))
            open_ = False
    if open_:
        out.append((lo, None, False))
    return out


def _le(a, b):
    try:
        return a <= b
    except TypeError:
        return False


def _lt(a, b):
    try:
        return a < b
    except TypeError:
        return False


def covers(eco, affected, version):
    """True if this OSV `affected` entry marks `version` as affected."""
    if str(version) in {str(x) for x in affected.get("versions", []) or []}:
        return True
    k = vkey(eco, version)
    if k is None:
        return False
    for rng in affected.get("ranges", []) or []:
        for lo, hi, inc in range_intervals(eco, rng):
            if lo is not None and not _le(lo, k):
                continue
            if hi is None or (inc and _le(k, hi)) or (not inc and _lt(k, hi)):
                return True
    return False


def last_affected_ends(rec, eco):
    """Yield (affected_entry, last_affected_version) for ranges whose final event is last_affected."""
    for aff in rec.get("affected", []) or []:
        pkg = aff.get("package", {}) or {}
        if pkg.get("ecosystem") != eco:
            continue
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            evs = rng.get("events", []) or []
            if evs and "last_affected" in evs[-1] and not any("fixed" in e for e in evs):
                yield aff, evs[-1]["last_affected"]


# ---------------------------------------------------------------- dates
def parse_ts(s):
    if not s:
        return None
    s = str(s).strip().replace("Z", "+00:00")
    try:
        d = datetime.fromisoformat(s)
    except ValueError:
        try:
            d = datetime.fromisoformat(s[:19])
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def classify(eco, rec, aff, last, releases, others):
    """releases: list of (version, upload datetime or None, yanked bool).
    others: list of second-database OSV records linked to this GHSA.
    Returns one row dict."""
    dbs = rec.get("database_specific", {}) or {}
    # The range is written when GitHub reviews the record; fall back to publication.
    pub = parse_ts(dbs.get("github_reviewed_at") or rec.get("published"))
    name = aff["package"]["name"]
    lk = vkey(eco, last)
    live = [(v, d) for v, d, y in releases if not y and vkey(eco, v) is not None]
    in_registry = any(v == str(last) for v, _, _ in releases)

    def newest(pred):
        cand = [(vkey(eco, v), v) for v, d in live if pred(v, d)]
        cand = [c for c in cand if c[0] is not None]
        return max(cand)[1] if cand else ""

    stable_at_pub = newest(lambda v, d: d is not None and pub is not None and d <= pub and not is_pre(eco, v))
    any_at_pub = newest(lambda v, d: d is not None and pub is not None and d <= pub)
    frozen = bool(pub) and str(last) in (stable_at_pub, any_at_pub)
    later = sorted(((vkey(eco, v), v, d) for v, d in live if lk is not None and _lt(lk, vkey(eco, v))),
                   key=lambda t: t[0])
    same_pkg = [a for a in rec.get("affected", []) or []
                if (a.get("package", {}) or {}).get("ecosystem") == eco
                and norm_name(eco, (a.get("package", {}) or {}).get("name", "")) == norm_name(eco, name)]
    uncovered = [(v, d) for _, v, d in later if not any(covers(eco, a, v) for a in same_pkg)]
    uncovered_stable = [(v, d) for v, d in uncovered if not is_pre(eco, v)]
    other_aff = []
    for o in others:
        for a in o.get("affected", []) or []:
            p = a.get("package", {}) or {}
            if p.get("ecosystem") == eco and norm_name(eco, p.get("name", "")) == norm_name(eco, name):
                other_aff.append((o["id"], a))
    disputed = [v for v, _ in uncovered if any(covers(eco, a, v) for _, a in other_aff)]
    other_fixed = sorted({ev["fixed"] for _, a in other_aff for r in a.get("ranges", []) or []
                          for ev in r.get("events", []) or [] if "fixed" in ev})
    latest = max(((vkey(eco, v), v, d) for v, d in live), default=(None, "", None),
                 key=lambda t: t[0]) if live else (None, "", None)
    first_later = uncovered_stable[0] if uncovered_stable else (uncovered[0] if uncovered else ("", None))
    return {
        "ecosystem": eco, "ghsa": rec["id"], "package": name,
        "aliases": " ".join(rec.get("aliases", []) or []),
        "severity": dbs.get("severity", ""),
        "published": (rec.get("published") or "")[:10],
        "reviewed": str(dbs.get("github_reviewed_at") or "")[:10],
        "modified": (rec.get("modified") or "")[:10],
        "last_affected": str(last), "last_affected_in_registry": in_registry,
        "newest_stable_at_publish": stable_at_pub, "newest_any_at_publish": any_at_pub,
        "frozen": frozen,
        "n_later_uncovered": len(uncovered), "n_later_uncovered_stable": len(uncovered_stable),
        "first_later_uncovered": first_later[0],
        "first_later_date": first_later[1].date().isoformat() if first_later[1] else "",
        "latest_version": latest[1], "latest_date": latest[2].date().isoformat() if latest[2] else "",
        "other_db_ids": " ".join(sorted({i for i, _ in other_aff})),
        "other_db_fixed": " ".join(other_fixed),
        "n_disputed": len(disputed), "disputed_sample": " ".join(disputed[:6]),
        "last_known_affected_version_range": str(dbs.get("last_known_affected_version_range", "")),
        "summary": " ".join(str(rec.get("summary", "")).split())[:140],
        "registry_versions": len(releases),
    }


# ---------------------------------------------------------------- registries
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
        time.sleep(1.05)  # crates.io crawler policy: 1 request per second
        if not doc:
            break
        for v in doc.get("versions", []) or []:
            out.append((v.get("num", ""), parse_ts(v.get("created_at")), bool(v.get("yanked"))))
        nxt = (doc.get("meta", {}) or {}).get("next_page")
        url = ("https://crates.io/api/v1/crates/%s/versions%s" % (urllib.parse.quote(name), nxt)) if nxt else None
    return out


def pypi_releases_from_doc(doc):
    out = []
    for ver, files in (doc.get("releases", {}) or {}).items():
        files = files or []
        dates = [parse_ts(f.get("upload_time_iso_8601") or f.get("upload_time")) for f in files]
        dates = [d for d in dates if d]
        yanked = bool(files) and all(f.get("yanked") for f in files)
        out.append((ver, min(dates) if dates else None, yanked))
    return out


def pypi_releases(name):
    doc = get_json("https://pypi.org/pypi/%s/json" % urllib.parse.quote(name))
    time.sleep(0.2)
    return pypi_releases_from_doc(doc) if doc else []


# ---------------------------------------------------------------- main
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
            if not n.endswith(".json"):
                continue
            base = os.path.basename(n)
            if not (base.startswith("GHSA-") or base.startswith("RUSTSEC-") or base.startswith("PYSEC-")):
                continue
            try:
                recs.append(json.loads(zf.read(n)))
            except ValueError:
                continue
    return recs


def link_others(ghsa_rec, by_alias):
    keys = {ghsa_rec["id"]} | set(ghsa_rec.get("aliases", []) or [])
    seen, out = set(), []
    for k in keys:
        for o in by_alias.get(k, []):
            if o["id"] not in seen:
                seen.add(o["id"])
                out.append(o)
    return out


def run_ecosystem(eco, recs, cap, cache):
    ghsas = [r for r in recs if r.get("id", "").startswith("GHSA-") and not r.get("withdrawn")]
    others = [r for r in recs if r.get("id", "").startswith(SECOND_DB[eco]) and not r.get("withdrawn")]
    by_alias = defaultdict(list)
    for o in others:
        for a in set(o.get("aliases", []) or []) | {o["id"]}:
            by_alias[a].append(o)
    targets = [(r, aff, last) for r in ghsas for aff, last in last_affected_ends(r, eco)]
    log(eco, "ghsa", len(ghsas), SECOND_DB[eco], len(others), "last_affected ranges", len(targets))
    rows, errors = [], Counter()
    names = sorted({aff["package"]["name"] for _, aff, _ in targets})
    for i, name in enumerate(names[:cap]):
        key = (eco, norm_name(eco, name))
        if key in cache:
            continue
        try:
            cache[key] = crates_releases(name) if eco == "crates.io" else pypi_releases(name)
        except Exception as e:  # keep going; record the failure
            errors[type(e).__name__] += 1
            cache[key] = None
        if i % 100 == 0:
            log(eco, "registry", i, "/", len(names))
    for r, aff, last in targets:
        rel = cache.get((eco, norm_name(eco, aff["package"]["name"])))
        if rel is None:
            errors["no_registry_data"] += 1
            continue
        rows.append(classify(eco, r, aff, last, rel, link_others(r, by_alias)))
    stats = {
        "ghsa_records": len(ghsas), "second_db_records": len(others),
        "ghsa_with_any_last_affected_end": len({r["id"] for r, _, _ in targets}),
        "last_affected_ranges": len(targets), "packages": len(names),
        "packages_capped": max(0, len(names) - cap), "rows": len(rows),
        "errors": dict(errors),
    }
    return rows, stats


def summarize(rows):
    s = Counter()
    for r in rows:
        s["rows"] += 1
        s["frozen"] += r["frozen"]
        if r["n_later_uncovered_stable"]:
            s["later_uncovered_stable"] += 1
            s["frozen_and_later_uncovered_stable"] += r["frozen"]
        if r["other_db_ids"]:
            s["with_second_db"] += 1
        if r["n_disputed"]:
            s["disputed"] += 1
            s["disputed_frozen"] += r["frozen"]
            s["disputed_high_or_critical"] += r["severity"] in ("HIGH", "CRITICAL")
        if not r["last_affected_in_registry"]:
            s["last_affected_not_in_registry"] += 1
    return dict(s)


def positive_control(rows):
    """uutils: GitHub-reviewed `coreutils` records with last_affected 0.8.0 (April 2026)."""
    ctl = [r for r in rows if r["ecosystem"] == "crates.io" and r["package"] == "coreutils"
           and r["last_affected"] == "0.8.0"]
    ok = [r for r in ctl if r["frozen"] and r["first_later_uncovered"] == "0.9.0"]
    return {"coreutils_0.8.0_rows": len(ctl), "frozen_with_0.9.0_first_later": len(ok)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--cap", type=int, default=4000, help="max packages per ecosystem to look up")
    args = ap.parse_args()
    os.makedirs(args.data_dir, exist_ok=True)
    os.makedirs(args.out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    all_rows, stats, cache = [], {"run_at": stamp}, {}
    for eco in ECOS:
        dest = os.path.join(args.data_dir, "s20-osv-%s-all.zip" % eco.replace(".", "-"))
        fetch(OSV_ZIP.format(eco=eco), dest)
        recs = load_osv(dest)
        rows, st = run_ecosystem(eco, recs, args.cap, cache)
        st.update(summarize(rows))
        stats[eco] = st
        all_rows.extend(rows)
        os.remove(dest)  # keep the shared dataset volume small; the export changes daily anyway
    if not all_rows:
        raise SystemExit("no rows: OSV export had no GHSA last_affected ranges (format change?)")
    stats["positive_control"] = positive_control(all_rows)
    all_rows.sort(key=lambda r: (r["ecosystem"], -r["n_disputed"], not r["frozen"], r["package"], r["ghsa"]))
    with open(os.path.join(args.out_dir, "rows.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        w.writeheader()
        w.writerows(all_rows)
    with open(os.path.join(args.out_dir, "summary.json"), "w") as f:
        json.dump(stats, f, indent=1)
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    sys.exit(main())
