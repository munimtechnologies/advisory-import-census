"""S9b (pre-registered): GitHub-CNA CVEs whose CVE record names one repository advisory as its source but links a
different one.

Two cases found by hand on 2026-11-06 UTC: seven Moquette CVEs (CVE-2026-95842..95848) and two Caddy CVEs
(CVE-2026-92284, CVE-2026-92700) carry a CNA "source.advisory" GHSA that is not public, while their only advisory
reference is an umbrella repository advisory (GHSA-5f42-97gr-vfhq, GHSA-j8px-rmrx-76h9) whose global entry lists a
different CVE. A lookup by any of those nine CVEs in GitHub's global Advisory Database returns nothing.

This counts the pattern over S8's population (GitHub-CNA CVEs published in NVD 2025-01-01..2026-09-30; S8's
cves.csv). For each CVE it reads the CVE record from CVE Services (cveawg.mitre.org) and classifies it:
  MATCH          containers.cna.source.advisory is a GHSA that is also cited in a repository-advisory reference
  SPLIT          source.advisory is a GHSA, the record cites at least one repository advisory, none of them it
  NO_REF         source.advisory is a GHSA but no repository-advisory reference is cited
  NO_SOURCE      no GHSA in source.advisory
  NOT_PUBLISHED  the record's state is not PUBLISHED
  NO_RECORD      CVE Services answers 404
  FETCH_ERROR    the record could not be read
For SPLIT rows the "umbrella" is the first cited repository advisory. Global-database facts come from a local
github/advisory-database clone (github-reviewed plus unreviewed 2025-2026, the same clone S8 used).

Inputs: S8's cves.csv (path or URL), a local clone, CVE Services. Ten seeded SPLIT source advisories are also
requested once from github.com (public page status only).
Outputs (--out-dir): rows.csv, records.jsonl, sample.csv, results.json, RESULTS-job.md. Stdlib only. Apache-2.0.
Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime
import hashlib
import json
import os
import random
import re
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CVES_URL = ("https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main/"
            "study/cna-gap-s8/cves.csv")
CVE_API = "https://cveawg.mitre.org/api/cve/%s"
REPO_ADV_PAGE = "https://github.com/%s/%s/security/advisories/%s"
UA = "advisory-import-census-s9b/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
GHSA_RE = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$", re.IGNORECASE)
REPO_ADV_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/security/advisories/"
    r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})", re.IGNORECASE)
EXPECTED_ROWS = 13769
MIN_FETCH = 0.98
# Checked by hand on 2026-11-06 UTC against cveawg.mitre.org (all are S8 population rows).
KNOWN = {"CVE-2026-95842": "SPLIT", "CVE-2026-95848": "SPLIT", "CVE-2026-92284": "SPLIT",
         "CVE-2026-92700": "SPLIT", "CVE-2026-57234": "MATCH"}
SEED = 20261106
SAMPLE_N = 10
CLASSES = ["MATCH", "SPLIT", "NO_REF", "NO_SOURCE", "NOT_PUBLISHED", "NO_RECORD", "FETCH_ERROR"]
UNCOVERED = ("NONE", "WITHDRAWN_ONLY")
LIVE_GLOBAL = ("REVIEWED", "UNREVIEWED")
ROW_COLS = ["cve", "nvd_published", "s8_coverage", "class", "state", "assigner", "source_ghsa", "ref_ghsas",
            "umbrella", "umbrella_owner", "umbrella_repo", "split_bundle", "source_global", "umbrella_global",
            "umbrella_aliases", "in_umbrella_aliases", "umbrella_own_cves"]
SAMPLE_COLS = ["cve", "source_ghsa", "umbrella_owner", "umbrella_repo", "page_url", "http_status"]


def norm_ghsa(g):
    parts = (g or "").strip().split("-")
    if len(parts) != 4 or parts[0].upper() != "GHSA":
        return (g or "").strip()
    return "GHSA-" + "-".join(p.lower() for p in parts[1:])


# ---------- CVE record side ----------

def repo_refs(refs):
    """Ordered unique repository-advisory GHSAs cited in a CNA references list, and their owner/repo."""
    order, where = [], {}
    for ref in refs or []:
        url = ref.get("url") if isinstance(ref, dict) else ""
        m = REPO_ADV_RE.search(url or "")
        if m:
            g = norm_ghsa(m.group(3))
            if g not in where:
                where[g] = (m.group(1), m.group(2))
                order.append(g)
    return order, where


def reduce_record(obj):
    """The fields S9b needs from one CVE JSON 5 record."""
    meta = obj.get("cveMetadata") or {}
    cna = (obj.get("containers") or {}).get("cna") or {}
    src = cna.get("source")
    raw = src.get("advisory") if isinstance(src, dict) else ""
    raw = raw.strip() if isinstance(raw, str) else ""
    refs, where = repo_refs(cna.get("references"))
    return {"state": meta.get("state") or "", "assigner": meta.get("assignerShortName") or "",
            "source_raw": raw, "source_ghsa": norm_ghsa(raw) if GHSA_RE.match(raw) else "",
            "ref_ghsas": refs, "where": where}


def source_class(rec):
    if rec["state"] != "PUBLISHED":
        return "NOT_PUBLISHED"
    if not rec["source_ghsa"]:
        return "NO_SOURCE"
    if not rec["ref_ghsas"]:
        return "NO_REF"
    if rec["source_ghsa"] in rec["ref_ghsas"]:
        return "MATCH"
    return "SPLIT"


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


def http_status(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return -1


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


# ---------- global database side ----------

def build_index(db_root):
    """GHSA -> (type, withdrawn, sorted CVE aliases) for every advisory file in the clone."""
    by_ghsa = {}
    for typ, sub in (("reviewed", "github-reviewed"), ("unreviewed", "unreviewed")):
        root = os.path.join(db_root, "advisories", sub)
        if not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not (fn.startswith("GHSA-") and fn.endswith(".json")):
                    continue
                try:
                    with open(os.path.join(dirpath, fn), encoding="utf-8") as fh:
                        adv = json.load(fh)
                except (OSError, ValueError):
                    continue
                aliases = sorted({a.upper() for a in adv.get("aliases") or [] if CVE_RE.match(a.upper())})
                by_ghsa[norm_ghsa(adv.get("id") or fn[:-5])] = (typ, bool(adv.get("withdrawn")), aliases)
    return by_ghsa


def global_state(g, by_ghsa):
    if not g:
        return ""
    v = by_ghsa.get(g)
    if v is None:
        return "NONE"
    return v[0].upper() + ("_WITHDRAWN" if v[1] else "")


# ---------- rows ----------

def read_pop(path):
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        c = (r.get("cve") or "").strip().upper()
        if c:
            out.append({"cve": c, "published": r.get("published") or "", "coverage": r.get("coverage") or ""})
    return out


def build_rows(pop, recs, by_ghsa):
    base = []
    for p in pop:
        status, rec = recs.get(p["cve"], ("FETCH_ERROR", None))
        if status == "NO_RECORD":
            cls = "NO_RECORD"
        elif rec is None:
            cls = "FETCH_ERROR"
        else:
            cls = source_class(rec)
        base.append((p, rec, cls))
    bundle, own = {}, {}
    for p, rec, cls in base:
        if cls == "SPLIT":
            u = rec["ref_ghsas"][0]
            bundle[u] = bundle.get(u, 0) + 1
        elif cls == "MATCH":
            own.setdefault(rec["source_ghsa"], []).append(p["cve"])
    rows = []
    for p, rec, cls in base:
        rec = rec or {"state": "", "assigner": "", "source_ghsa": "", "ref_ghsas": [], "where": {}}
        umb = rec["ref_ghsas"][0] if cls == "SPLIT" else ""
        owner, repo = rec["where"].get(umb, ("", "")) if umb else ("", "")
        u = by_ghsa.get(umb) if umb else None
        rows.append({
            "cve": p["cve"], "nvd_published": p["published"], "s8_coverage": p["coverage"], "class": cls,
            "state": rec["state"], "assigner": rec["assigner"], "source_ghsa": rec["source_ghsa"],
            "ref_ghsas": ";".join(rec["ref_ghsas"]), "umbrella": umb, "umbrella_owner": owner,
            "umbrella_repo": repo, "split_bundle": bundle.get(umb, 0) if umb else 0,
            "source_global": global_state(rec["source_ghsa"], by_ghsa) if cls == "SPLIT" else "",
            "umbrella_global": global_state(umb, by_ghsa),
            "umbrella_aliases": ";".join(u[2]) if u else "",
            "in_umbrella_aliases": ("yes" if p["cve"] in u[2] else "no") if u else "",
            "umbrella_own_cves": ";".join(sorted(own.get(umb, []))) if umb else ""})
    return rows


# ---------- grading ----------

def pct(k, n):
    return [k, n, round(100.0 * k / n, 2) if n else None]


CLAIMS = {
    "P1": "SPLIT CVEs are between 0.2% and 3% of population CVEs whose record was read",
    "P2": ">= 95% of MATCH+SPLIT CVEs are MATCH",
    "P3": ">= 90% of SPLIT CVEs name a source advisory that is absent from the global database clone",
    "P4": ">= 70% of SPLIT CVEs had no live global advisory in S8 (coverage NONE or WITHDRAWN_ONLY)",
    "P5": ">= 60% of SPLIT CVEs share their umbrella advisory with at least one other SPLIT CVE",
    "P6": ">= 80% of SPLIT CVEs whose umbrella is a live global advisory are not in that advisory's aliases",
}


def grade(rows):
    read = [r for r in rows if r["class"] != "FETCH_ERROR"]
    split = [r for r in rows if r["class"] == "SPLIT"]
    match = [r for r in rows if r["class"] == "MATCH"]
    live = [r for r in split if r["umbrella_global"] in LIVE_GLOBAL]
    v = {
        "P1": pct(len(split), len(read)),
        "P2": pct(len(match), len(match) + len(split)),
        "P3": pct(sum(1 for r in split if r["source_global"] == "NONE"), len(split)),
        "P4": pct(sum(1 for r in split if r["s8_coverage"] in UNCOVERED), len(split)),
        "P5": pct(sum(1 for r in split if r["split_bundle"] >= 2), len(split)),
        "P6": pct(sum(1 for r in live if r["in_umbrella_aliases"] == "no"), len(live)),
    }
    k1, n1 = v["P1"][0], v["P1"][1]
    held = {"P1": bool(n1) and 0.2 * n1 <= 100.0 * k1 <= 3.0 * n1}
    for pid, lo in (("P2", 95), ("P3", 90), ("P4", 70), ("P5", 60), ("P6", 80)):
        k, n = v[pid][0], v[pid][1]
        held[pid] = bool(n) and 100 * k >= lo * n
    return [{"id": pid, "claim": CLAIMS[pid], "value": v[pid], "held": held[pid]} for pid in sorted(CLAIMS)]


def gate(rows, known=KNOWN, expected_rows=EXPECTED_ROWS, min_fetch=MIN_FETCH):
    by = {r["cve"]: r for r in rows}
    read = sum(1 for r in rows if r["class"] != "FETCH_ERROR")
    checks = {"rows": len(rows) == expected_rows,
              "read_share": bool(rows) and read >= min_fetch * len(rows),
              "known_cases": all(c in by and by[c]["class"] == k for c, k in known.items())}
    return all(checks.values()), checks


# ---------- descriptive ----------

def count_by(items, fn, top=None):
    out = {}
    for x in items:
        k = fn(x)
        out[k] = out.get(k, 0) + 1
    pairs = sorted(out.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return dict(pairs[:top] if top else pairs)


def pick_sample(rows, n=SAMPLE_N, seed=SEED):
    seen, pool = set(), []
    for r in sorted((r for r in rows if r["class"] == "SPLIT"), key=lambda r: r["cve"]):
        if r["source_ghsa"] not in seen:
            seen.add(r["source_ghsa"])
            pool.append(r)
    if len(pool) <= n:
        return pool
    return sorted(random.Random(seed).sample(pool, n), key=lambda r: r["cve"])


def read_sample(sample, status=http_status, pause=2.0):
    out = []
    for r in sample:
        url = REPO_ADV_PAGE % (r["umbrella_owner"], r["umbrella_repo"], r["source_ghsa"])
        code = status(url)
        out.append({"cve": r["cve"], "source_ghsa": r["source_ghsa"], "umbrella_owner": r["umbrella_owner"],
                    "umbrella_repo": r["umbrella_repo"], "page_url": url, "http_status": code})
        if pause:
            time.sleep(pause)
    return out


def describe(rows, sample_rows):
    split = [r for r in rows if r["class"] == "SPLIT"]
    umbrellas = {}
    for r in split:
        umbrellas.setdefault(r["umbrella"], r)
    return {
        "population_rows": len(rows),
        "class": {c: sum(1 for r in rows if r["class"] == c) for c in CLASSES},
        "assigner_of_read": count_by([r for r in rows if r["assigner"]], lambda r: r["assigner"]),
        "split_umbrellas": len(umbrellas),
        "split_umbrellas_with_own_match_cve": sum(1 for r in umbrellas.values() if r["umbrella_own_cves"]),
        "split_source_global": count_by(split, lambda r: r["source_global"]),
        "split_umbrella_global": count_by(split, lambda r: r["umbrella_global"]),
        "split_s8_coverage": count_by(split, lambda r: r["s8_coverage"]),
        "split_by_nvd_month": dict(sorted(count_by(split, lambda r: r["nvd_published"][:7]).items())),
        "split_top_umbrellas": count_by(split, lambda r: "%s/%s %s" % (r["umbrella_owner"], r["umbrella_repo"],
                                                                         r["umbrella"]), top=25),
        "split_bundle_sizes": dict(sorted(count_by(umbrellas.values(), lambda r: r["split_bundle"]).items())),
        "sample_http_status": count_by(sample_rows, lambda s: s["http_status"]),
    }


# ---------- outputs ----------

def write_csv(path, cols, items):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in items:
            w.writerow([r[c] for c in cols])


def write_outputs(out_dir, rows, recs, sample_rows, preds, desc, gate_ok, checks, meta):
    os.makedirs(out_dir, exist_ok=True)
    write_csv(os.path.join(out_dir, "rows.csv"), ROW_COLS, rows)
    write_csv(os.path.join(out_dir, "sample.csv"), SAMPLE_COLS, sample_rows)
    with open(os.path.join(out_dir, "records.jsonl"), "w", encoding="utf-8") as f:
        for cve in sorted(recs):
            status, rec = recs[cve]
            line = {"cve": cve, "status": status}
            if rec:
                line.update({"state": rec["state"], "assigner": rec["assigner"], "source_raw": rec["source_raw"],
                             "ref_ghsas": rec["ref_ghsas"]})
            f.write(json.dumps(line) + "\n")
    res = {"meta": meta, "gate_ok": gate_ok, "gate_checks": checks, "predictions": preds, "descriptive": desc}
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    lines = ["# S9b: GitHub-CNA CVEs whose record names a different source advisory than it links (job output)", "",
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


def fetch_file(url, dest):
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


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cves", default=CVES_URL, help="S8 cves.csv path or URL")
    ap.add_argument("--db-root", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    t = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.makedirs(args.out_dir, exist_ok=True)
    path = args.cves
    if path.startswith("http"):
        path = fetch_file(path, os.path.join(args.out_dir, "input-cves.csv"))
    pop = read_pop(path)
    by_ghsa = build_index(args.db_root)
    recs = fetch_all([p["cve"] for p in pop], http_get, workers=args.workers)
    rows = build_rows(pop, recs, by_ghsa)
    ok, checks = gate(rows)
    preds = grade(rows)
    sample_rows = read_sample(pick_sample(rows))
    desc = describe(rows, sample_rows)
    meta = {"db_head": db_head(args.db_root), "cves_source": args.cves, "cves_sha256": sha256(path),
            "read_at": t, "global_advisories_indexed": len(by_ghsa), "seed": SEED}
    write_outputs(args.out_dir, rows, recs, sample_rows, preds, desc, ok, checks, meta)
    print("done: gate %s %s; classes %s" % (ok, json.dumps(checks), json.dumps(desc["class"])))
    for p in preds:
        print(p["id"], p["value"], "held" if p["held"] else "not held")


if __name__ == "__main__":
    main()
