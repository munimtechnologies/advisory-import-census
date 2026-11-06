"""S9a (pre-registered): when GitHub's CNA publishes a CVE after the GitHub-reviewed advisory it cites, how often
does that global advisory list the CVE?

S8 found 65 live GitHub-reviewed advisories with no CVE alias although GitHub's CNA published a CVE for that same
advisory (study/cna-gap-s8-alias). 65 has no denominator: this counts every S8 population CVE (GitHub-CNA CVEs
published in NVD 2025-01-01..2026-09-30, S8's cves.csv) whose first cited repository advisory is a live
GitHub-reviewed global advisory, and asks, for the CVEs published at least one calendar day AFTER that advisory went
global ("late" CVEs), what share the advisory still does not list.

Statuses (one per population CVE):
  LISTS_THIS                 the cited reviewed advisory lists exactly this CVE
  LISTS_THIS_AND_OTHERS      it lists this CVE and others
  LISTS_NONE                 it lists no CVE, and no live reviewed advisory holds the CVE (the S8-alias gap)
  LISTS_NONE_HELD_ELSEWHERE  it lists no CVE, but another reviewed advisory holds the CVE
  LISTS_OTHER                it lists a different CVE only
  REF_WITHDRAWN              the cited advisory is withdrawn
  REF_NOT_REVIEWED           the cited advisory is not a GitHub-reviewed file in the clone
  NO_REF                     the CVE cites no repository advisory
ELIGIBLE = LISTS_THIS or LISTS_NONE, and no other population CVE cites the same advisory. MISSING = LISTS_NONE.
lag_days = NVD published date of the CVE minus the advisory's "published" date (UTC calendar days); late = lag >= 1.

Inputs: S8's cves.csv (path or URL) and a local github/advisory-database clone. No other network use.
Outputs (--out-dir): rows.csv, results.json, RESULTS-job.md. Stdlib only. Apache-2.0.
Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime
import hashlib
import json
import os
import re
import subprocess
import urllib.request

CVES_URL = ("https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main/"
            "study/cna-gap-s8/cves.csv")
UA = "advisory-import-census-s9a/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
JUNE_BATCH = ("2026-06-18", "2026-06-19")
JUNE_JULY = ("2026-06-01", "2026-07-31")
LAG_SPLIT = 30
EXPECTED = {"rows": 13769, "reviewed": 7699, "global_without_alias": 78}
MISSING_GATE = (62, 68)
STATUSES = ["LISTS_THIS", "LISTS_THIS_AND_OTHERS", "LISTS_NONE", "LISTS_NONE_HELD_ELSEWHERE", "LISTS_OTHER",
            "REF_WITHDRAWN", "REF_NOT_REVIEWED", "NO_REF"]
OUT_COLS = ["cve", "nvd_published", "ref_owner", "ref_repo", "ref_ghsa", "status", "bundle_size", "eligible",
            "missing", "adv_published", "adv_modified", "adv_reviewed_at", "lag_days", "late",
            "modified_on_or_after_cve"]


def norm_ghsa(g):
    parts = (g or "").strip().split("-")
    if len(parts) != 4 or parts[0].upper() != "GHSA":
        return (g or "").strip()
    return "GHSA-" + "-".join(p.lower() for p in parts[1:])


def index_files(root):
    """GHSA ID -> path of its JSON file under root."""
    out = {}
    if not root or not os.path.isdir(root):
        return out
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if fn.startswith("GHSA-") and fn.endswith(".json"):
                out[norm_ghsa(fn[:-5])] = os.path.join(dirpath, fn)
    return out


def load_adv(path):
    with open(path, encoding="utf-8") as fh:
        adv = json.load(fh)
    ds = adv.get("database_specific") or {}
    return {"aliases": sorted({a.upper() for a in adv.get("aliases") or [] if CVE_RE.match(a.upper())}),
            "published": adv.get("published") or "", "modified": adv.get("modified") or "",
            "withdrawn": adv.get("withdrawn") or "", "reviewed_at": ds.get("github_reviewed_at") or ""}


def day(s):
    return (s or "")[:10]


def lag_days(adv_published, cve_published):
    try:
        a = datetime.date.fromisoformat(day(adv_published))
        b = datetime.date.fromisoformat(day(cve_published))
    except ValueError:
        return None
    return (b - a).days


def read_cves(path):
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["cve"] = (r.get("cve") or "").strip().upper()
        r["ref_ghsa"] = norm_ghsa(r.get("ref_ghsa") or "")
    return rows


def classify_rows(rows, files, load=load_adv):
    bundle = {}
    for r in rows:
        if r["ref_ghsa"]:
            bundle[r["ref_ghsa"]] = bundle.get(r["ref_ghsa"], 0) + 1
    cache, out = {}, []
    for r in rows:
        g = r["ref_ghsa"]
        adv = None
        if not g:
            status = "NO_REF"
        elif g not in files:
            status = "REF_NOT_REVIEWED"
        else:
            if g not in cache:
                cache[g] = load(files[g])
            adv = cache[g]
            if adv["withdrawn"]:
                status = "REF_WITHDRAWN"
            elif r["cve"] in adv["aliases"]:
                status = "LISTS_THIS" if adv["aliases"] == [r["cve"]] else "LISTS_THIS_AND_OTHERS"
            elif not adv["aliases"]:
                status = "LISTS_NONE_HELD_ELSEWHERE" if r.get("coverage") == "REVIEWED" else "LISTS_NONE"
            else:
                status = "LISTS_OTHER"
        eligible = status in ("LISTS_THIS", "LISTS_NONE") and bundle.get(g, 0) == 1
        a = adv or {"published": "", "modified": "", "reviewed_at": ""}
        lag = lag_days(a["published"], r.get("published", "")) if adv else None
        out.append({"cve": r["cve"], "nvd_published": r.get("published", ""), "ref_owner": r.get("ref_owner", ""),
                    "ref_repo": r.get("ref_repo", ""), "ref_ghsa": g, "status": status,
                    "bundle_size": bundle.get(g, 0) if g else 0, "eligible": "yes" if eligible else "no",
                    "missing": "yes" if status == "LISTS_NONE" else "no",
                    "adv_published": a["published"], "adv_modified": a["modified"],
                    "adv_reviewed_at": a["reviewed_at"], "lag_days": "" if lag is None else lag,
                    "late": "yes" if (lag is not None and lag >= 1) else "no",
                    "modified_on_or_after_cve": "yes" if (adv and day(a["modified"]) >= day(r.get("published", "")))
                    else "no"})
    return out


def rate(rows):
    n = len(rows)
    m = sum(1 for r in rows if r["missing"] == "yes")
    return [m, n, round(100.0 * m / n, 2) if n else None]


def in_range(d, lo_hi):
    return lo_hi[0] <= day(d) <= lo_hi[1]


def grade(out):
    el = [r for r in out if r["eligible"] == "yes"]
    late = [r for r in el if r["late"] == "yes"]
    june = [r for r in late if in_range(r["adv_published"], JUNE_BATCH)]
    outside = [r for r in late if not in_range(r["adv_published"], JUNE_JULY)]
    long_ = [r for r in late if int(r["lag_days"]) >= LAG_SPLIT]
    short = [r for r in late if int(r["lag_days"]) < LAG_SPLIT]
    aliased_late = [r for r in late if r["missing"] == "no"]
    p1, p2, p3, pl, ps = rate(late), rate(june), rate(outside), rate(long_), rate(short)
    p5 = [len(late), len(el), round(100.0 * len(late) / len(el), 2) if el else None]
    mod = sum(1 for r in aliased_late if r["modified_on_or_after_cve"] == "yes")
    p6 = [mod, len(aliased_late), round(100.0 * mod / len(aliased_late), 2) if aliased_late else None]
    preds = [
        {"id": "P1", "claim": "<= 10% of eligible late CVEs are MISSING", "value": p1,
         "held": bool(p1[1]) and p1[0] * 100 <= 10 * p1[1]},
        {"id": "P2", "claim": ">= 30% of eligible late CVEs whose advisory was published 2026-06-18..19 are MISSING",
         "value": p2, "held": bool(p2[1]) and p2[0] * 100 >= 30 * p2[1]},
        {"id": "P3", "claim": "<= 3% of eligible late CVEs whose advisory was published outside 2026-06-01..07-31 "
                              "are MISSING", "value": p3, "held": bool(p3[1]) and p3[0] * 100 <= 3 * p3[1]},
        {"id": "P4", "claim": "MISSING rate for lag >= 30 days is higher than for lag 1-29 days",
         "value": {"lag_ge_30": pl, "lag_1_29": ps},
         "held": bool(pl[1]) and bool(ps[1]) and pl[0] * ps[1] > ps[0] * pl[1]},
        {"id": "P5", "claim": "late CVEs are between 2% and 20% of eligible CVEs", "value": p5,
         "held": bool(p5[1]) and 2 * p5[1] <= p5[0] * 100 <= 20 * p5[1]},
        {"id": "P6", "claim": ">= 50% of eligible late CVEs that ARE listed sit in an advisory whose 'modified' date "
                              "is on or after the CVE's NVD published date", "value": p6,
         "held": bool(p6[1]) and p6[0] * 100 >= 50 * p6[1]},
    ]
    return preds


def describe(rows, out):
    el = [r for r in out if r["eligible"] == "yes"]
    late = [r for r in el if r["late"] == "yes"]
    by_month = {}
    for r in late:
        k = day(r["adv_published"])[:7]
        by_month.setdefault(k, [0, 0])
        by_month[k][1] += 1
        by_month[k][0] += r["missing"] == "yes"
    bins = {"1-6": (1, 6), "7-29": (7, 29), "30-89": (30, 89), "90+": (90, 10 ** 6)}
    lag_bins = {k: rate([r for r in late if lo <= int(r["lag_days"]) <= hi]) for k, (lo, hi) in bins.items()}
    not_late = [r for r in el if r["late"] == "no"]
    return {"population_rows": len(rows),
            "coverage_reviewed": sum(1 for r in rows if r.get("coverage") == "REVIEWED"),
            "global_without_alias": sum(1 for r in rows if r.get("uncovered_kind") == "GLOBAL_WITHOUT_ALIAS"),
            "status": {s: sum(1 for r in out if r["status"] == s) for s in STATUSES},
            "eligible": len(el), "eligible_missing": sum(1 for r in el if r["missing"] == "yes"),
            "late": len(late), "late_missing": sum(1 for r in late if r["missing"] == "yes"),
            "not_late": rate(not_late),
            "late_by_adv_month_missing_of_n": dict(sorted(by_month.items())),
            "late_by_lag_days": lag_bins}


def gate(desc, expected=EXPECTED, missing_gate=MISSING_GATE):
    checks = {"rows": desc["population_rows"] == expected["rows"],
              "reviewed": desc["coverage_reviewed"] == expected["reviewed"],
              "global_without_alias": desc["global_without_alias"] == expected["global_without_alias"],
              "eligible_missing_in_range": missing_gate[0] <= desc["eligible_missing"] <= missing_gate[1]}
    return all(checks.values()), checks


def fetch(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    with open(dest, "wb") as f:
        f.write(data)
    return dest


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def db_head(root):
    try:
        return subprocess.run(["git", "-C", root, "log", "-1", "--format=%H %cI"], check=True,
                              capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def write_outputs(out_dir, out, preds, desc, gate_ok, checks, meta):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "rows.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(OUT_COLS)
        for r in out:
            if r["status"] in ("NO_REF", "REF_NOT_REVIEWED"):
                continue
            w.writerow([r[c] for c in OUT_COLS])
    res = {"meta": meta, "gate_ok": gate_ok, "gate_checks": checks, "predictions": preds, "descriptive": desc}
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    lines = ["# S9a: do late GitHub-CNA CVEs reach the reviewed advisory they cite? (job output)", "",
             "advisory-database %s; cves.csv sha256 %s; run %s." % (meta["db_head"], meta["cves_sha256"],
                                                                   meta["read_at"]), "",
             "Gate: %s %s" % ("PASSED" if gate_ok else "FAILED (predictions not graded)", json.dumps(checks)), "",
             "| Prediction | Claim | Value | Held |", "|---|---|---|---|"]
    for p in preds:
        lines.append("| %s | %s | %s | %s |" % (p["id"], p["claim"], json.dumps(p["value"]),
                                                ("yes" if p["held"] else "no") if gate_ok else "not graded"))
    lines += ["", "Descriptive: %s" % json.dumps(desc)]
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cves", default=CVES_URL, help="S8 cves.csv path or URL")
    ap.add_argument("--db-root", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    t = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    path = args.cves
    if path.startswith("http"):
        os.makedirs(args.out_dir, exist_ok=True)
        path = fetch(path, os.path.join(args.out_dir, "input-cves.csv"))
    rows = read_cves(path)
    files = index_files(os.path.join(args.db_root, "advisories", "github-reviewed"))
    out = classify_rows(rows, files)
    desc = describe(rows, out)
    ok, checks = gate(desc)
    preds = grade(out)
    meta = {"db_head": db_head(args.db_root), "cves_source": args.cves, "cves_sha256": sha256(path),
            "read_at": t, "reviewed_files_indexed": len(files)}
    write_outputs(args.out_dir, out, preds, desc, ok, checks, meta)
    print("done: gate %s %s; eligible %d (missing %d); late %d (missing %d)" % (
        ok, json.dumps(checks), desc["eligible"], desc["eligible_missing"], desc["late"], desc["late_missing"]))
    for p in preds:
        print(p["id"], p["value"], "held" if p["held"] else "not held")


if __name__ == "__main__":
    main()
