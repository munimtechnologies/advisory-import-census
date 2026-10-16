#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Munim, Inc.
"""Re-verify the advisory-import-census against the live OSV database.

The census (out/gra_census.csv) records, for each published GitHub Security
Advisory (GHSA) of a target repository, whether it is present in the global
database under its own GHSA id (column ``in_global_db``). OSV (api.osv.dev)
mirrors that global database, so querying OSV for a GHSA id is an independent,
dated check of the same fact:

    HTTP 200  -> the advisory is in the global database   (present)
    HTTP 404  -> it is not                                (missing)

This tool re-queries OSV today and reports, per the census snapshot:

  * how many advisories the census marked missing are *still* missing
    (the persistence of the import gap), and
  * how many it marked present are *still* present (a positive control that
    validates OSV as a proxy for the census measurement).

It is deliberately dependency-free (standard library only) and gentle on OSV
(one request at a time with a small pause). Run it in a sandbox or locally:

    python -I reverify.py --census out/gra_census.csv --out out/reverify.json

Disclosure: written by AI agents working in the name of MV2 of Munim, Inc.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Callable, Iterable

OSV_URL = "https://api.osv.dev/v1/vulns/{ghsa}"

TRUE_STRINGS = {"true", "1", "yes", "y", "t"}
FALSE_STRINGS = {"false", "0", "no", "n", "f", ""}


def parse_bool(value: str) -> bool:
    """Parse a CSV truthy/falsey cell. Raises ValueError on anything else."""
    v = (value or "").strip().lower()
    if v in TRUE_STRINGS:
        return True
    if v in FALSE_STRINGS:
        return False
    raise ValueError(f"not a boolean: {value!r}")


def read_census(path: str) -> list[dict]:
    """Read the census CSV into a list of {repo, ghsa_id, severity, in_global_db}."""
    rows: list[dict] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for raw in reader:
            ghsa = (raw.get("ghsa_id") or "").strip()
            if not ghsa:
                continue
            rows.append(
                {
                    "repo": (raw.get("repo") or "").strip(),
                    "ghsa_id": ghsa,
                    "severity": (raw.get("severity") or "").strip(),
                    "in_global_db": parse_bool(raw.get("in_global_db", "")),
                }
            )
    return rows


def osv_status_http(ghsa: str, timeout: float = 30.0) -> str:
    """Return 'present' (HTTP 200) or 'missing' (HTTP 404) for a GHSA on OSV."""
    url = OSV_URL.format(ghsa=ghsa)
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return "present" if resp.status == 200 else f"http_{resp.status}"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "missing"
        return f"http_{exc.code}"


def classify(expected_in_db: bool, observed_status: str) -> str:
    """Compare the census expectation with what OSV now returns.

    Returns one of:
      'still_missing'  census said missing, OSV still 404
      'imported_since' census said missing, OSV now 200 (gap closed)
      'still_present'  census said present, OSV still 200
      'dropped_since'  census said present, OSV now 404 (regression)
      'inconclusive'   OSV returned neither 200 nor 404
    """
    if observed_status not in ("present", "missing"):
        return "inconclusive"
    if expected_in_db:
        return "still_present" if observed_status == "present" else "dropped_since"
    return "imported_since" if observed_status == "present" else "still_missing"


def summarize(results: Iterable[dict]) -> dict:
    """Aggregate per-row verdicts into counts and the headline persistence rate."""
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    missing_checked = counts.get("still_missing", 0) + counts.get("imported_since", 0)
    present_checked = counts.get("still_present", 0) + counts.get("dropped_since", 0)
    agree = counts.get("still_missing", 0) + counts.get("still_present", 0)
    checked = missing_checked + present_checked
    return {
        "counts": counts,
        "missing_checked": missing_checked,
        "present_checked": present_checked,
        "still_missing": counts.get("still_missing", 0),
        "imported_since": counts.get("imported_since", 0),
        "gap_persistence": (
            counts.get("still_missing", 0) / missing_checked if missing_checked else None
        ),
        "proxy_agreement": agree / checked if checked else None,
    }


def run(
    rows: list[dict],
    fetch: Callable[[str], str],
    pause: float = 0.5,
    also_present: bool = True,
) -> list[dict]:
    """Query each row (missing always; present if also_present) and classify it."""
    out: list[dict] = []
    for row in rows:
        if not also_present and row["in_global_db"]:
            continue
        status = fetch(row["ghsa_id"])
        out.append(
            {
                **row,
                "osv_status": status,
                "verdict": classify(row["in_global_db"], status),
            }
        )
        if pause:
            time.sleep(pause)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--census", default="out/gra_census.csv", help="path to gra_census.csv")
    ap.add_argument("--out", default="out/reverify.json", help="where to write the JSON report")
    ap.add_argument("--limit", type=int, default=0, help="check at most N rows (0 = all)")
    ap.add_argument("--pause", type=float, default=0.5, help="seconds between OSV requests")
    ap.add_argument(
        "--missing-only",
        action="store_true",
        help="skip the in_global_db=true positive-control rows",
    )
    args = ap.parse_args(argv)

    rows = read_census(args.census)
    if args.limit:
        rows = rows[: args.limit]

    results = run(rows, osv_status_http, pause=args.pause, also_present=not args.missing_only)
    report = {
        "checked_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "census": args.census,
        "n_rows": len(results),
        "summary": summarize(results),
        "rows": results,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
