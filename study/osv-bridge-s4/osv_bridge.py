"""OSV bridge check (pre-registered study S4, see PREREG.md).

Question: for the CVE lookups that miss packages in the GitHub Advisory Database (studies S2 and S3),
does OSV.dev link the CVE to the GitHub-reviewed record? S3 found 648 pairs where a reviewed GHSA has
no CVE alias and the CVE sits only on an unreviewed twin with no packages; S2 found 96 pairs where a
reviewed GHSA links to a CVE that another reviewed GHSA holds. For every pair this asks OSV.dev for
the GHSA record and for the CVE record and checks whether either points at the other.

Data:
  - study/late-cve-s3/pairs.csv and study/cve-lookup-s2/pairs.csv from
    munimtechnologies/advisory-import-census (row counts are checked; SHA-256 is recorded).
  - GET https://api.osv.dev/v1/vulns/{id} for every GHSA and CVE in those pairs (cached per id).

Outputs (--out-dir): results.json, RESULTS.md, rows.csv.
Stdlib only. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import time
import urllib.error
import urllib.request

RAW = "https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main/"
S3_URL = RAW + "study/late-cve-s3/pairs.csv"
S2_URL = RAW + "study/cve-lookup-s2/pairs.csv"
S3_ROWS = 648
S2_ROWS = 96
OSV_URL = "https://api.osv.dev/v1/vulns/"
UA = "advisory-import-census-osv-bridge/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
ERROR = "error"
MAX_ERROR_SHARE = 0.05


# ---------- fetching ----------

def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def fetch_csv(url, wait_minutes=0, sleep=60, get=http_get):
    """Rows of a CSV at url and the SHA-256 of its bytes. Waits while the URL returns 404."""
    deadline = time.time() + wait_minutes * 60
    while True:
        try:
            raw = get(url)
            break
        except urllib.error.HTTPError as e:
            if e.code != 404 or time.time() >= deadline:
                raise
            time.sleep(sleep)
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"))))
    return rows, hashlib.sha256(raw).hexdigest()


def check_rows(rows, expected, columns):
    """Refuse inputs that are not the frozen files."""
    if len(rows) != expected:
        raise ValueError("expected %d rows, got %d" % (expected, len(rows)))
    for c in columns:
        if rows and c not in rows[0]:
            raise ValueError("missing column %s" % c)


def osv_get(vid, get=http_get, cache=None, tries=3, pause=2.0, delay=0.05):
    """OSV record for vid as a dict, None if OSV returns 404, ERROR if it keeps failing."""
    if cache is not None and vid in cache:
        return cache[vid]
    out = ERROR
    for i in range(tries):
        if delay:
            time.sleep(delay)
        try:
            out = json.loads(get(OSV_URL + vid).decode("utf-8"))
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                out = None
                break
        except (urllib.error.URLError, OSError, ValueError):
            pass
        out = ERROR
        if pause:
            time.sleep(pause * (i + 1))
    if cache is not None:
        cache[vid] = out
    return out


# ---------- checks ----------

def status(rec):
    if rec is None:
        return "missing"
    if rec == ERROR:
        return "error"
    return "ok"


def links(rec, target, fields=("aliases", "related", "upstream")):
    """True if an OSV record is target or names target in one of fields."""
    if not isinstance(rec, dict):
        return False
    if rec.get("id") == target:
        return True
    for f in fields:
        if target in (rec.get(f) or []):
            return True
    return False


def has_package(rec):
    """True if an OSV record names at least one ecosystem package."""
    if not isinstance(rec, dict):
        return False
    for a in rec.get("affected") or []:
        p = a.get("package") or {}
        if p.get("name") and p.get("ecosystem"):
            return True
    return False


def check_pairs(pairs, osv, side, ghsa_fields):
    """pairs: list of (ghsa, cve). One output row per pair."""
    out = []
    for ghsa, cve in pairs:
        g = osv(ghsa)
        c = osv(cve)
        out.append({
            "side": side, "ghsa": ghsa, "cve": cve,
            "ghsa_status": status(g), "cve_status": status(c),
            "ghsa_lists_cve": links(g, cve, ghsa_fields),
            "cve_links_ghsa": links(c, ghsa),
            "cve_has_package": has_package(c),
        })
    return out


def share(rows, key):
    """(k, n, percent, errors) over rows where neither lookup errored."""
    ok = [r for r in rows if r["ghsa_status"] != "error" and r["cve_status"] != "error"]
    n = len(ok)
    k = sum(1 for r in ok if r[key])
    return k, n, (round(100.0 * k / n, 1) if n else None), len(rows) - n


def verdict(rows, key, op, threshold):
    k, n, pct, err = share(rows, key)
    if n == 0 or err > MAX_ERROR_SHARE * len(rows):
        held = "INCONCLUSIVE_ERRORS"
    elif op == ">=":
        held = "yes" if pct >= threshold else "no"
    else:
        held = "yes" if pct <= threshold else "no"
    return {"value": [k, n, pct], "errors": err, "held": held}


CLAIMS = {
    "Q1": ("s3", "ghsa_lists_cve", ">=", 90.0,
           ">= 90% of S3 pairs: OSV's record of the reviewed GHSA lists the twin's CVE in aliases"),
    "Q2": ("s3", "cve_links_ghsa", ">=", 90.0,
           ">= 90% of S3 pairs: OSV's record of the CVE is or names the reviewed GHSA "
           "(aliases, related or upstream)"),
    "Q3": ("s2", "ghsa_lists_cve", "<=", 20.0,
           "<= 20% of S2 pairs: OSV's record of the hidden GHSA names the CVE (aliases, related or upstream)"),
    "Q4": ("s2", "cve_links_ghsa", "<=", 20.0,
           "<= 20% of S2 pairs: OSV's record of the CVE is or names the hidden GHSA "
           "(aliases, related or upstream)"),
}


def verdicts(rows):
    out = {}
    for q, (side, key, op, thr, claim) in CLAIMS.items():
        v = verdict([r for r in rows if r["side"] == side], key, op, thr)
        v["claim"] = claim
        out[q] = v
    return out


def descriptive(rows):
    d = {}
    for side in ("s3", "s2"):
        rs = [r for r in rows if r["side"] == side]
        ok = [r for r in rs if r["ghsa_status"] != "error" and r["cve_status"] != "error"]
        d[side] = {
            "pairs": len(rs),
            "ghsa_missing_on_osv": sum(1 for r in rs if r["ghsa_status"] == "missing"),
            "cve_missing_on_osv": sum(1 for r in rs if r["cve_status"] == "missing"),
            "either_direction": sum(1 for r in ok if r["ghsa_lists_cve"] or r["cve_links_ghsa"]),
            "neither_direction": sum(1 for r in ok if not (r["ghsa_lists_cve"] or r["cve_links_ghsa"])),
            "cve_record_names_a_package": sum(1 for r in ok if r["cve_has_package"]),
        }
    return d


# ---------- outputs ----------

ROW_FIELDS = ["side", "ghsa", "cve", "ghsa_status", "cve_status", "ghsa_lists_cve",
              "cve_links_ghsa", "cve_has_package"]


def write_outputs(out_dir, rows, v, d, meta):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "verdicts": v, "descriptive": d}, f, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, "rows.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ROW_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow(r)
    lines = ["# OSV bridge check S4: results", "",
             "Inputs: S3 pairs.csv sha256 %s; S2 pairs.csv sha256 %s. OSV queried %s to %s." % (
                 meta["s3_sha256"], meta["s2_sha256"], meta["started"], meta["finished"]), "",
             "| Prediction | Claim | Value [k, n, %] | Errors | Held |", "|---|---|---|---|---|"]
    for q in sorted(v):
        lines.append("| %s | %s | %s | %d | %s |" % (q, v[q]["claim"], v[q]["value"], v[q]["errors"],
                                                     v[q]["held"]))
    lines += ["", "Descriptive: " + json.dumps(d, sort_keys=True), ""]
    with open(os.path.join(out_dir, "RESULTS.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--wait-minutes", type=int, default=180,
                    help="wait this long for the S3 pairs.csv to appear on GitHub")
    a = ap.parse_args(argv)
    s3, s3_sha = fetch_csv(S3_URL, a.wait_minutes)
    s2, s2_sha = fetch_csv(S2_URL, 10)
    check_rows(s3, S3_ROWS, ("reviewed", "twin", "cve"))
    check_rows(s2, S2_ROWS, ("ghsa", "cve"))
    cache = {}

    def osv(vid):
        return osv_get(vid, cache=cache)

    started = now()
    rows = check_pairs([(r["reviewed"], r["cve"]) for r in s3], osv, "s3", ("aliases",))
    rows += check_pairs([(r["ghsa"], r["cve"]) for r in s2], osv, "s2",
                        ("aliases", "related", "upstream"))
    meta = {"s3_url": S3_URL, "s2_url": S2_URL, "s3_sha256": s3_sha, "s2_sha256": s2_sha,
            "started": started, "finished": now(), "osv_ids_queried": len(cache)}
    write_outputs(a.out_dir, rows, verdicts(rows), descriptive(rows), meta)
    print("done: outputs written to %s" % a.out_dir)


if __name__ == "__main__":
    main()
