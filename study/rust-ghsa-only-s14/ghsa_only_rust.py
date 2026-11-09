#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ghsa_only_rust.py: which GitHub-reviewed Rust advisories have no RustSec counterpart?

Study S14 of https://github.com/munimtechnologies/advisory-import-census (pre-registered in
study/rust-ghsa-only-s14/PREREG.md). cargo-audit and cargo-deny read only the RustSec Advisory
Database, so a crates.io advisory that exists only in GitHub's Advisory Database is invisible to
them. This script reads OSV's public crates.io export (one zip holding both GHSA and RUSTSEC
records), decides for every GitHub-reviewed, non-withdrawn crates.io GHSA record whether RustSec
covers it, and writes the counts the pre-registered predictions are graded on.

Covered, in this order (first match is the reason):
  alias_in_ghsa     the GHSA record lists a RUSTSEC ID in aliases or related
  alias_in_rustsec  a RUSTSEC record lists the GHSA ID in aliases or related
  shared_cve        a RUSTSEC record shares a CVE ID with the GHSA record
  reference         the GHSA record links to rustsec.org/advisories/RUSTSEC-... or rustsec/advisory-db
Otherwise the row is GHSA_ONLY. A match only through a withdrawn RUSTSEC record is reported as
covered_withdrawn (RustSec decided against it), never as GHSA_ONLY.

Standard library only. Made with AI agents working in MV2's (Munim, Inc.) name.
"""
import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import random
import re
import sys
import time
import urllib.request
import zipfile

__version__ = "0.1.0"

ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip"
CUTOFF = "2026-10-01"           # rows published on/after this are reported, not graded (sync lag)
RECENT = ("2025-01-01", "2026-09-30")
OLD = ("2019-01-01", "2022-12-31")
SEED = 20261109
SAMPLE_N = 8
GATE_MIN_RUSTSEC = 500
GATE_MIN_GHSA = 300

RUSTSEC_REF_RE = re.compile(r"rustsec\.org/advisories/RUSTSEC-|github\.com/rustsec/advisory-db", re.I)
REPO_ADV_RE = re.compile(r"^https?://github\.com/[^/]+/[^/]+/security/advisories/GHSA-", re.I)
DOS_CWES = {"CWE-400", "CWE-401", "CWE-404", "CWE-674", "CWE-770", "CWE-772", "CWE-789", "CWE-834",
            "CWE-835", "CWE-1050", "CWE-1333", "CWE-248", "CWE-703", "CWE-754", "CWE-617"}


def ids_of(rec, prefix):
    out = set()
    for key in ("aliases", "related"):
        for v in rec.get(key) or []:
            if isinstance(v, str) and v.upper().startswith(prefix):
                out.add(v.upper() if prefix == "CVE-" else v)
    return out


def crates_of(rec):
    names = []
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") == "crates.io" and pkg.get("name") and pkg["name"] not in names:
            names.append(pkg["name"])
    return names


def load_records(zip_bytes):
    recs = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                recs.append(json.loads(zf.read(name).decode("utf-8")))
            except ValueError:
                continue
    return recs


def classify(recs):
    """Return (rows for every eligible GHSA record, counts dict)."""
    rustsec = [r for r in recs if str(r.get("id", "")).startswith("RUSTSEC-")]
    ghsa_all = [r for r in recs if str(r.get("id", "")).startswith("GHSA-")]
    by_ghsa, by_cve = {}, {}
    for r in rustsec:
        for g in ids_of(r, "GHSA-"):
            by_ghsa.setdefault(g.lower(), []).append(r)
        for c in ids_of(r, "CVE-"):
            by_cve.setdefault(c, []).append(r)
    live_crates = set()
    for r in rustsec:
        if not r.get("withdrawn"):
            live_crates.update(crates_of(r))

    eligible = []
    for g in ghsa_all:
        ds = g.get("database_specific") or {}
        if g.get("withdrawn") or ds.get("github_reviewed") is not True or not crates_of(g):
            continue
        eligible.append(g)

    rows = []
    for g in sorted(eligible, key=lambda r: r["id"]):
        ds = g.get("database_specific") or {}
        cves = sorted(ids_of(g, "CVE-"))
        refs = [x.get("url", "") for x in g.get("references") or [] if isinstance(x, dict)]
        reason, via_withdrawn = None, False
        if ids_of(g, "RUSTSEC-"):
            reason = "alias_in_ghsa"
        else:
            hits = by_ghsa.get(g["id"].lower(), [])
            if hits:
                reason = "alias_in_rustsec"
                via_withdrawn = all(h.get("withdrawn") for h in hits)
            else:
                hits = [h for c in cves for h in by_cve.get(c, [])]
                if hits:
                    reason = "shared_cve"
                    via_withdrawn = all(h.get("withdrawn") for h in hits)
                elif any(RUSTSEC_REF_RE.search(u or "") for u in refs):
                    reason = "reference"
        if reason is None:
            status = "GHSA_ONLY"
        elif via_withdrawn:
            status = "COVERED_WITHDRAWN"
        else:
            status = "COVERED"
        crates = crates_of(g)
        cwes = [c for c in ds.get("cwe_ids") or [] if isinstance(c, str)]
        rows.append({
            "ghsa_id": g["id"],
            "status": status,
            "reason": reason or "",
            "published": (g.get("published") or "")[:10],
            "github_reviewed_at": (ds.get("github_reviewed_at") or "")[:10],
            "severity": ds.get("severity") or "",
            "cwe_ids": ";".join(cwes),
            "dos_like": "yes" if any(c in DOS_CWES for c in cwes) else "no",
            "crates": ";".join(crates),
            "crate_in_rustsec": "yes" if any(c in live_crates for c in crates) else "no",
            "cve_ids": ";".join(cves),
            "repo_advisory": "yes" if any(REPO_ADV_RE.match(u or "") for u in refs) else "no",
        })
    counts = {
        "records": len(recs), "rustsec_records": len(rustsec), "ghsa_records": len(ghsa_all),
        "eligible_ghsa": len(rows),
    }
    return rows, counts


def share(rows, lo, hi):
    sub = [r for r in rows if lo <= r["published"] <= hi]
    only = sum(1 for r in sub if r["status"] == "GHSA_ONLY")
    return {"n": len(sub), "ghsa_only": only, "share": (only / len(sub)) if sub else None}


def grade(rows):
    graded = [r for r in rows if r["published"] and r["published"] < CUTOFF]
    only = [r for r in graded if r["status"] == "GHSA_ONLY"]
    n = len(only)
    recent, old = share(graded, *RECENT), share(graded, *OLD)
    diff = None
    if recent["share"] is not None and old["share"] is not None:
        diff = recent["share"] - old["share"]
    repo_adv = sum(1 for r in only if r["repo_advisory"] == "yes")
    high = sum(1 for r in only if r["severity"] in ("HIGH", "CRITICAL"))
    crates = set()
    for r in only:
        crates.update(c for c in r["crates"].split(";") if c)
    preds = {
        "P1_ghsa_only_at_least_100": {"value": n, "held": n >= 100},
        "P2_recent_minus_old_at_least_10pts": {
            "recent": recent, "old": old, "diff_pts": None if diff is None else round(100 * diff, 1),
            "held": None if diff is None else diff >= 0.10},
        "P3_repo_advisory_share_at_least_50pct": {
            "value": repo_adv, "of": n, "share": (repo_adv / n) if n else None,
            "held": (repo_adv / n >= 0.50) if n else None},
        "P4_high_or_critical_share_at_least_30pct": {
            "value": high, "of": n, "share": (high / n) if n else None,
            "held": (high / n >= 0.30) if n else None},
        "P5_distinct_crates_at_least_50": {"value": len(crates), "held": len(crates) >= 50},
        "P6_hand_check": {"held": None, "note": "graded by hand from sample.csv, at least 6 of 8"},
    }
    sample_pool = sorted(r["ghsa_id"] for r in only)
    rng = random.Random(SEED)
    sample = sorted(rng.sample(sample_pool, min(SAMPLE_N, len(sample_pool))))
    return graded, only, preds, sample


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


FIELDS = ["ghsa_id", "status", "reason", "published", "github_reviewed_at", "severity", "cwe_ids",
          "dos_like", "crates", "crate_in_rustsec", "cve_ids", "repo_advisory"]


def fetch_zip(url, dest, tries=4):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "advisory-import-census-s14/" + __version__})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
            with open(dest, "wb") as fh:
                fh.write(data)
            return data
        except OSError as exc:  # URLError is an OSError
            last = exc
            time.sleep(5 * (i + 1))
    raise SystemExit("download failed: %s" % last)


def run(zip_bytes, out_dir, provenance):
    recs = load_records(zip_bytes)
    rows, counts = classify(recs)
    gate = {
        "rustsec_records": counts["rustsec_records"], "min_rustsec": GATE_MIN_RUSTSEC,
        "eligible_ghsa": counts["eligible_ghsa"], "min_ghsa": GATE_MIN_GHSA,
    }
    gate["passed"] = (counts["rustsec_records"] >= GATE_MIN_RUSTSEC
                      and counts["eligible_ghsa"] >= GATE_MIN_GHSA)
    os.makedirs(out_dir, exist_ok=True)
    result = {"version": __version__, "provenance": provenance, "counts": counts, "gate": gate}
    write_csv(os.path.join(out_dir, "rows.csv"), rows, FIELDS)
    if gate["passed"]:
        graded, only, preds, sample = grade(rows)
        reasons = {}
        for r in graded:
            key = r["status"] + ("/" + r["reason"] if r["reason"] else "")
            reasons[key] = reasons.get(key, 0) + 1
        late = [r for r in rows if r["published"] >= CUTOFF]
        result.update({
            "graded_rows": len(graded), "ghsa_only": len(only), "status_reason_counts": reasons,
            "predictions": preds, "sample": sample,
            "exploratory": {
                "ghsa_only_dos_like": sum(1 for r in only if r["dos_like"] == "yes"),
                "ghsa_only_crate_in_rustsec": sum(1 for r in only if r["crate_in_rustsec"] == "yes"),
                "ghsa_only_with_cve": sum(1 for r in only if r["cve_ids"]),
                "rows_on_or_after_cutoff": len(late),
                "ghsa_only_on_or_after_cutoff": sum(1 for r in late if r["status"] == "GHSA_ONLY"),
                "ghsa_only_by_year": by_year(only),
                "eligible_by_year": by_year(graded),
            },
        })
        write_csv(os.path.join(out_dir, "sample.csv"),
                  [r for r in only if r["ghsa_id"] in sample], FIELDS)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as fh:
        fh.write(render(result))
    return result


def by_year(rows):
    out = {}
    for r in rows:
        y = r["published"][:4] or "unknown"
        out[y] = out.get(y, 0) + 1
    return dict(sorted(out.items()))


def render(res):
    lines = ["# S14 job output (machine-written, not yet graded by hand)", "",
             "Script ghsa_only_rust.py %s. Made with AI agents working in MV2's (Munim, Inc.) name." % res["version"],
             "", "Provenance: `%s`" % json.dumps(res["provenance"], sort_keys=True), "",
             "Counts: `%s`" % json.dumps(res["counts"], sort_keys=True), "",
             "Gate: %s (`%s`)" % ("PASSED" if res["gate"]["passed"] else "FAILED",
                                  json.dumps(res["gate"], sort_keys=True)), ""]
    if res["gate"]["passed"]:
        lines += ["Graded rows (GHSA published before %s): %d; GHSA_ONLY: %d" % (CUTOFF, res["graded_rows"], res["ghsa_only"]), "",
                  "| prediction | result | held |", "|---|---|---|"]
        for k, v in res["predictions"].items():
            shown = {kk: vv for kk, vv in v.items() if kk != "held"}
            lines.append("| %s | `%s` | %s |" % (k, json.dumps(shown, sort_keys=True), v["held"]))
        lines += ["", "Status/reason counts: `%s`" % json.dumps(res["status_reason_counts"], sort_keys=True), "",
                  "Exploratory (not predicted): `%s`" % json.dumps(res["exploratory"], sort_keys=True), "",
                  "Seeded hand-check sample (seed %d): %s" % (SEED, ", ".join(res["sample"]))]
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--data-dir", default="data")
    p.add_argument("--out-dir", default="out")
    p.add_argument("--zip", help="use this local zip instead of downloading")
    p.add_argument("--version", action="store_true")
    a = p.parse_args(argv)
    if a.version:
        print("ghsa_only_rust.py " + __version__)
        return 0
    os.makedirs(a.data_dir, exist_ok=True)
    fetched = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if a.zip:
        with open(a.zip, "rb") as fh:
            data = fh.read()
        src = a.zip
    else:
        dest = os.path.join(a.data_dir, "crates-io-all-%s.zip" % fetched[:10])
        data = fetch_zip(ZIP_URL, dest)
        src = ZIP_URL
    prov = {"source": src, "fetched_utc": fetched, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}
    res = run(data, a.out_dir, prov)
    print(render(res))
    return 0 if res["gate"]["passed"] else 3


if __name__ == "__main__":
    sys.exit(main())
