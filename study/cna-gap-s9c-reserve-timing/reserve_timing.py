"""S9c (pre-registered): was the CVE ID already reserved when GitHub reviewed the advisory it cites?

S9a found that 64 of 3,685 eligible "late" GitHub-CNA CVEs (CVE published in NVD at least a day after the reviewed
global advisory it cites) are missing from that advisory's aliases. Hand checks on 2026-11-06 UTC suggest two routes:
the CVE ID can exist (RESERVED) when the advisory is reviewed, so it is written in at review time, or it can be
reserved only after review, so the alias has to be added later. This reads each late CVE's record from CVE Services
(cveawg.mitre.org) and compares dateReserved with the advisory's github_reviewed_at:
  BEFORE   dateReserved <= github_reviewed_at (falls back to the advisory's published time if reviewed_at is empty)
  AFTER    dateReserved >  github_reviewed_at
  UNKNOWN  record missing, not PUBLISHED, or a timestamp could not be read
It also records whether the CNA source.advisory is the advisory S9a cites (S9b's SPLIT pattern).

Input: S9a's rows.csv (path or URL; the study/cna-gap-s9a/ copy on the repository's main branch by default).
Outputs (--out-dir): rows.csv, results.json, RESULTS-job.md. Stdlib only. Apache-2.0.
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

AMENDMENT 1 (2026-11-07 UTC, see AMENDMENT.md): EXPECTED_ROWS was 13769, the size of S9a's population, but S9a's
published rows.csv holds only the 7,770 rows that cite a GitHub-reviewed global advisory, so v1's gate failed on
that check alone. The constant is now 7770 and the input's sha256 is pinned to the file v1 read. Nothing else
changed: population, definitions, predictions and the other gate checks are as pre-registered.
"""
import argparse
import csv
import datetime
import hashlib
import io
import json
import os
import re
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROWS_URL = ("https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main/"
            "study/cna-gap-s9a/rows.csv")
CVE_API = "https://cveawg.mitre.org/api/cve/%s"
UA = "advisory-import-census-s9c/1.1 (MV2, Munim, Inc.; mv2@munimtech.com)"
REPO_ADV_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/security/advisories/"
    r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})", re.IGNORECASE)
GHSA_RE = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$", re.IGNORECASE)
EXPECTED_ROWS = 7770   # AMENDMENT 1: rows in S9a's published rows.csv (was 13769, S9a's population size)
EXPECTED_SHA256 = "897fb04c44b650d991d61691eec5b70ed1bfef9ea36b5ef8069f2fc2d56f8117"  # AMENDMENT 1: v1's input
EXPECTED_LATE = 3685
EXPECTED_LATE_MISSING = 64
MIN_FETCH = 0.98
WINDOW = ("2026-06-01", "2026-07-31")
# Checked by hand on 2026-11-06 UTC (cveawg dateReserved vs api.github.com github_reviewed_at).
KNOWN = {"CVE-2026-57204": "AFTER", "CVE-2025-55300": "AFTER", "CVE-2026-48019": "BEFORE",
         "CVE-2026-48113": "BEFORE", "CVE-2026-54899": "BEFORE"}
OUT_COLS = ["cve", "nvd_published", "ref_ghsa", "status", "missing", "adv_published", "adv_reviewed_at",
            "adv_modified", "lag_days", "in_window", "fetch", "state", "date_reserved", "date_published",
            "timing", "source_ghsa", "source_matches_ref", "modified_after_reserved"]


def norm_ghsa(g):
    parts = (g or "").strip().split("-")
    if len(parts) != 4 or parts[0].upper() != "GHSA":
        return (g or "").strip()
    return "GHSA-" + "-".join(p.lower() for p in parts[1:])


def parse_ts(s):
    """Naive UTC datetime from '2026-06-24T02:00:46.801Z', '2026-06-18T14:28:49Z', '...+00:00' or '2026-06-18'."""
    s = (s or "").strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1]
    if s.endswith("+00:00"):
        s = s[:-6]
    if "." in s:
        s = s.split(".")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def reduce_record(obj):
    meta = obj.get("cveMetadata") or {}
    cna = (obj.get("containers") or {}).get("cna") or {}
    src = cna.get("source")
    raw = src.get("advisory") if isinstance(src, dict) else ""
    raw = raw.strip() if isinstance(raw, str) else ""
    refs = []
    for ref in cna.get("references") or []:
        url = ref.get("url") if isinstance(ref, dict) else ""
        m = REPO_ADV_RE.search(url or "")
        if m and norm_ghsa(m.group(3)) not in refs:
            refs.append(norm_ghsa(m.group(3)))
    return {"state": meta.get("state") or "", "reserved": meta.get("dateReserved") or "",
            "published": meta.get("datePublished") or "",
            "source_ghsa": norm_ghsa(raw) if GHSA_RE.match(raw) else "", "ref_ghsas": refs}


# ---------- HTTP ----------

def http_get(url, timeout=60, tries=4, pause=5.0):
    """(status, parsed JSON or None). 404 is returned at once; other failures are retried."""
    last = 0
    for i in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return 404, None
            last = e.code
        except (urllib.error.URLError, OSError, ValueError):
            last = -1
        time.sleep(pause * (i + 1))
    return last, None


def get_text(url, tries=45, pause=120.0):
    """Text of url. Waits on 404 because the input may be committed shortly after this job is filed."""
    for i in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read().decode("utf-8")
        except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
            print("input not readable yet (%s), try %d of %d" % (e, i + 1, tries), flush=True)
        time.sleep(pause)
    raise SystemExit("input %s never became readable" % url)


def fetch_one(cve, get):
    code, obj = get(CVE_API % cve)
    if code == 200 and isinstance(obj, dict):
        return cve, ("OK", reduce_record(obj))
    if code == 404:
        return cve, ("NO_RECORD", None)
    return cve, ("FETCH_ERROR", None)


def fetch_all(cves, get, workers=4):
    out = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for cve, res in ex.map(lambda c: fetch_one(c, get), cves):
            out[cve] = res
    for cve in [c for c in cves if out[c][0] == "FETCH_ERROR"]:   # one slow second pass
        out[cve] = fetch_one(cve, get)[1]
    return out


# ---------- classification ----------

def read_rows_text(text):
    return list(csv.DictReader(io.StringIO(text)))


def population(rows):
    return [r for r in rows if r.get("eligible") == "yes" and r.get("late") == "yes"]


def in_window(adv_published, window=WINDOW):
    d = (adv_published or "")[:10]
    return "yes" if d and window[0] <= d <= window[1] else "no"


def timing(row, rec):
    if not rec or rec.get("state") != "PUBLISHED":
        return "UNKNOWN"
    res = parse_ts(rec.get("reserved"))
    rev = parse_ts(row.get("adv_reviewed_at") or row.get("adv_published"))
    if res is None or rev is None:
        return "UNKNOWN"
    return "BEFORE" if res <= rev else "AFTER"


def source_matches(row, rec):
    if not rec or not rec.get("source_ghsa"):
        return ""
    return "yes" if rec["source_ghsa"] == norm_ghsa(row.get("ref_ghsa")) else "no"


def modified_after_reserved(row, rec):
    if not rec:
        return ""
    res, mod = parse_ts(rec.get("reserved")), parse_ts(row.get("adv_modified"))
    if res is None or mod is None:
        return ""
    return "yes" if mod >= res else "no"


def build(pop, recs):
    out = []
    for r in pop:
        status, rec = recs.get(r["cve"], ("FETCH_ERROR", None))
        out.append({
            "cve": r["cve"], "nvd_published": r.get("nvd_published", ""), "ref_ghsa": r.get("ref_ghsa", ""),
            "status": r.get("status", ""), "missing": r.get("missing", ""),
            "adv_published": r.get("adv_published", ""), "adv_reviewed_at": r.get("adv_reviewed_at", ""),
            "adv_modified": r.get("adv_modified", ""), "lag_days": r.get("lag_days", ""),
            "in_window": in_window(r.get("adv_published")), "fetch": status,
            "state": rec["state"] if rec else "", "date_reserved": rec["reserved"] if rec else "",
            "date_published": rec["published"] if rec else "", "timing": timing(r, rec),
            "source_ghsa": rec["source_ghsa"] if rec else "", "source_matches_ref": source_matches(r, rec),
            "modified_after_reserved": modified_after_reserved(r, rec)})
    return out


# ---------- grading ----------

def pct(k, n):
    return [k, n, round(100.0 * k / n, 2) if n else None]


def grade(out):
    known = [r for r in out if r["timing"] in ("BEFORE", "AFTER")]
    listed = [r for r in known if r["missing"] == "no"]
    miss = [r for r in known if r["missing"] == "yes"]
    after = [r for r in known if r["timing"] == "AFTER"]
    after_in = [r for r in after if r["in_window"] == "yes"]
    after_out = [r for r in after if r["in_window"] == "no"]
    after_listed = [r for r in after if r["missing"] == "no"]
    before_miss = [r for r in miss if r["timing"] == "BEFORE"]

    def held(v, test):
        return None if v[2] is None else bool(test(v[2]))

    p = []
    v = pct(sum(r["timing"] == "BEFORE" for r in listed), len(listed))
    p.append({"id": "Q1", "claim": ">= 80% of eligible late LISTED CVEs were reserved BEFORE review",
              "value": v, "held": held(v, lambda x: x >= 80)})
    v = pct(len(after_listed), len(after))
    p.append({"id": "Q2", "claim": ">= 50% of eligible late CVEs reserved AFTER review are LISTED (alias added later)",
              "value": v, "held": held(v, lambda x: x >= 50)})
    v = pct(sum(r["timing"] == "AFTER" for r in miss), len(miss))
    p.append({"id": "Q3", "claim": ">= 60% of eligible late MISSING CVEs were reserved AFTER review",
              "value": v, "held": held(v, lambda x: x >= 60)})
    vin = pct(sum(r["missing"] == "yes" for r in after_in), len(after_in))
    vout = pct(sum(r["missing"] == "yes" for r in after_out), len(after_out))
    q4 = None if vin[2] is None or vout[2] is None else vin[2] > vout[2]
    p.append({"id": "Q4", "claim": "among AFTER CVEs, the MISSING rate is higher for advisories published "
              "2026-06-01..07-31 than outside", "value": {"in_window": vin, "outside": vout}, "held": q4})
    v = pct(sum(r["modified_after_reserved"] == "yes" for r in after_listed), len(after_listed))
    p.append({"id": "Q5", "claim": ">= 95% of AFTER CVEs that are LISTED sit in an advisory modified on or after "
              "dateReserved", "value": v, "held": held(v, lambda x: x >= 95)})
    v = pct(sum(r["source_matches_ref"] == "no" for r in before_miss), len(before_miss))
    p.append({"id": "Q6", "claim": ">= 30% of BEFORE MISSING CVEs name a different GHSA as CNA source.advisory",
              "value": v, "held": held(v, lambda x: x >= 30)})
    return p


def gate(rows, pop, out, expected_rows=EXPECTED_ROWS, expected_late=EXPECTED_LATE,
         expected_missing=EXPECTED_LATE_MISSING, min_fetch=MIN_FETCH, known=KNOWN):
    by = {r["cve"]: r for r in out}
    ok_fetch = sum(r["fetch"] == "OK" for r in out)
    checks = {
        "rows": len(rows) == expected_rows,
        "late": len(pop) == expected_late,
        "late_missing": sum(r.get("missing") == "yes" for r in pop) == expected_missing,
        "fetch": bool(out) and ok_fetch / float(len(out)) >= min_fetch,
        "known": all(by[c]["timing"] == t for c, t in known.items() if c in by),
    }
    return all(checks.values()), checks


def describe(out):
    d = {"population": len(out), "fetch": {}, "timing_by_status": {}, "source_mismatch_by_timing_status": {},
         "after_listed_days_reserved_to_modified": None, "by_adv_month": {}}
    for r in out:
        d["fetch"][r["fetch"]] = d["fetch"].get(r["fetch"], 0) + 1
        key = "%s|%s" % (r["timing"], "MISSING" if r["missing"] == "yes" else "LISTED")
        d["timing_by_status"][key] = d["timing_by_status"].get(key, 0) + 1
        if r["source_matches_ref"] == "no":
            d["source_mismatch_by_timing_status"][key] = d["source_mismatch_by_timing_status"].get(key, 0) + 1
        m = (r["adv_published"] or "")[:7]
        cell = d["by_adv_month"].setdefault(m, {"BEFORE": [0, 0], "AFTER": [0, 0], "UNKNOWN": [0, 0]})
        cell[r["timing"]][1] += 1
        if r["missing"] == "yes":
            cell[r["timing"]][0] += 1
    days = []
    for r in out:
        if r["timing"] == "AFTER" and r["missing"] == "no":
            a, b = parse_ts(r["date_reserved"]), parse_ts(r["adv_modified"])
            if a and b:
                days.append((b - a).total_seconds() / 86400.0)
    if days:
        days.sort()
        d["after_listed_days_reserved_to_modified"] = {
            "n": len(days), "median": round(statistics.median(days), 2), "min": round(days[0], 2),
            "max": round(days[-1], 2)}
    return d


def write_outputs(out_dir, out, preds, desc, gate_ok, checks, meta):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rows.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_COLS)
        w.writeheader()
        for r in out:
            w.writerow({c: r[c] for c in OUT_COLS})
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "gate": {"passed": gate_ok, "checks": checks},
                   "predictions": preds if gate_ok else [], "descriptive": desc}, f, indent=1)
    lines = ["# S9c: was the CVE ID reserved before GitHub reviewed the advisory? (job output)", "",
             "Input %s sha256 %s; run %s." % (meta["input"], meta["input_sha256"], meta["run_at"]), "",
             "Gate: %s %s" % ("PASSED" if gate_ok else "FAILED (predictions not graded)", json.dumps(checks)), ""]
    if gate_ok:
        lines += ["| Prediction | Claim | Value | Held |", "|---|---|---|---|"]
        for p in preds:
            h = "n/a" if p["held"] is None else ("yes" if p["held"] else "no")
            lines.append("| %s | %s | %s | %s |" % (p["id"], p["claim"], json.dumps(p["value"]), h))
    lines += ["", "Descriptive: %s" % json.dumps(desc)]
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", default=ROWS_URL, help="S9a rows.csv path or URL")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    if a.rows.startswith("http"):
        text = get_text(a.rows)
    else:
        with open(a.rows, encoding="utf-8") as f:
            text = f.read()
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    rows = read_rows_text(text)
    pop = population(rows)
    print("rows %d, eligible late %d; reading CVE records" % (len(rows), len(pop)), flush=True)
    recs = fetch_all([r["cve"] for r in pop], http_get, workers=a.workers)
    out = build(pop, recs)
    ok, checks = gate(rows, pop, out)
    checks["input_sha256"] = sha == EXPECTED_SHA256   # AMENDMENT 1: same input file as v1
    ok = ok and checks["input_sha256"]
    preds = grade(out)
    desc = describe(out)
    meta = {"input": a.rows, "input_sha256": sha, "amendment": 1,
            "run_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    write_outputs(a.out_dir, out, preds, desc, ok, checks, meta)
    print("done: gate %s %s" % (ok, json.dumps(checks)))
    if ok:
        for p in preds:
            print(p["id"], json.dumps(p["value"]), "n/a" if p["held"] is None else ("held" if p["held"] else "not held"))


if __name__ == "__main__":
    main()
