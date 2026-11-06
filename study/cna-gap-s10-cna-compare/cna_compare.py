"""Does a CVE that cites a GitHub repository advisory reach GitHub's Advisory Database less often when GitHub's own
CNA issued it? Pre-registered study S10 (control arm for S8). See PREREG.md.

Population: every NVD record published 2025-01-01..2026-09-30 (not Rejected) whose references include a
repository advisory URL github.com/<owner>/<repo>/security/advisories/GHSA-... . Arm G: NVD sourceIdentifier is
security-advisories@github.com (GitHub's CNA, `GitHub_M`). Arm O: any other source. Both arms are matched against
the same github/advisory-database checkout (github-reviewed + unreviewed 2025-2026), which this job does NOT
update (other queued jobs share it); its commit is recorded. A seeded live sample of 10 + 10 CVEs is read from
GET /advisories?cve_id= to check the checkout against the live API.

Outputs (--out-dir): results.json, RESULTS-job.md, rows.csv, sample.csv.
Stdlib only. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime
import json
import os
import random
import re
import statistics
import subprocess
import time
import urllib.error
import urllib.request

DB_URL = "https://github.com/github/advisory-database.git"
SPARSE = ["advisories/github-reviewed", "advisories/unreviewed/2025", "advisories/unreviewed/2026"]
NVD_RANGE = ("https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=%sT00:00:00.000"
             "&pubEndDate=%sT23:59:59.999&resultsPerPage=%d&startIndex=%d")
GH_BY_CVE = "https://api.github.com/advisories?cve_id=%s"
UA = "advisory-import-census-s10/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
GITHUB_SOURCE = "security-advisories@github.com"
PAGE = 2000
NVD_PAUSE = 7.0          # NVD without a key: 5 requests per rolling 30 s
GH_PAUSE = 1.5
WINDOW = ("2025-01-01", "2026-09-30")
SEED = 20261106
SAMPLE_N = 10            # per arm
MIN_FETCH = 0.95
MIN_ARM_O = 100
MIN_STRATUM = 30
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
REPO_ADV_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/security/advisories/"
    r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})", re.IGNORECASE)


def norm_ghsa(g):
    parts = g.split("-")
    return "GHSA-" + "-".join(p.lower() for p in parts[1:])


# ---------- HTTP ----------

def http_get(url, timeout=180, tries=5, pause=10.0, accept="application/json"):
    """(status, parsed JSON or None). 404 is returned at once; other failures are retried."""
    last = 0
    for i in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
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


def gh_get(url):
    return http_get(url, timeout=60, tries=2, pause=5.0, accept="application/vnd.github+json")


# ---------- NVD side ----------

def month_chunks(window=WINDOW):
    """Calendar-month (start, end) date strings covering the window (NVD allows at most 120 days per query)."""
    y, m = int(window[0][:4]), int(window[0][5:7])
    out = []
    while True:
        start = datetime.date(y, m, 1)
        nxt = datetime.date(y + (m == 12), m % 12 + 1, 1)
        end = nxt - datetime.timedelta(days=1)
        s, e = max(start.isoformat(), window[0]), min(end.isoformat(), window[1])
        if s > window[1]:
            break
        out.append((s, e))
        y, m = nxt.year, nxt.month
    return out


def reduce_nvd(cve):
    refs = [r.get("url") or "" for r in cve.get("references") or []]
    repo_advs, seen = [], set()
    for u in refs:
        mm = REPO_ADV_RE.search(u)
        if mm:
            g = norm_ghsa(mm.group(3))
            if g not in seen:
                seen.add(g)
                repo_advs.append({"owner": mm.group(1), "repo": mm.group(2), "ghsa": g})
    return {"cve": (cve.get("id") or "").upper(), "source": (cve.get("sourceIdentifier") or "").lower(),
            "published": (cve.get("published") or "")[:10], "status": cve.get("vulnStatus") or "",
            "repo_advs": repo_advs}


def fetch_nvd(get, chunks, pause=NVD_PAUSE, page=PAGE):
    """Records citing a repository advisory, plus counts. Returns (records, total_reported, fetched, failed,
    per_source_all) where per_source_all counts every fetched record by source (for context)."""
    keep, total_all, fetched, failed, per_source = {}, 0, 0, 0, {}
    first = True
    for s, e in chunks:
        start, total = 0, None
        while total is None or start < total:
            if pause and not first:
                time.sleep(pause)
            first = False
            code, obj = get(NVD_RANGE % (s, e, page, start))
            if code != 200 or not isinstance(obj, dict):
                failed += 1
                if total is None:
                    break
                start += page
                continue
            if total is None:
                total = int(obj.get("totalResults") or 0)
                total_all += total
            vulns = obj.get("vulnerabilities") or []
            for v in vulns:
                rec = reduce_nvd(v.get("cve") or {})
                if not rec["cve"]:
                    continue
                fetched += 1
                per_source[rec["source"]] = per_source.get(rec["source"], 0) + 1
                if rec["repo_advs"]:
                    keep[rec["cve"]] = rec
            if not vulns:
                break
            start += len(vulns)
    return [keep[k] for k in sorted(keep)], total_all, fetched, failed, per_source


def in_window(rec, window=WINDOW):
    return window[0] <= rec["published"] <= window[1] and rec["status"].lower() != "rejected"


def arm_of(rec):
    return "G" if rec["source"] == GITHUB_SOURCE else "O"


# ---------- global database side ----------

def build_index(roots):
    """by_cve[CVE] = list of (ghsa, type, withdrawn, published); by_ghsa[GHSA] = (type, withdrawn, aliases)."""
    by_cve, by_ghsa = {}, {}
    for typ, root in roots.items():
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            for fn in files:
                if not (fn.startswith("GHSA-") and fn.endswith(".json")):
                    continue
                try:
                    with open(os.path.join(dirpath, fn), encoding="utf-8") as fh:
                        adv = json.load(fh)
                except (OSError, ValueError):
                    continue
                gid = norm_ghsa(adv.get("id") or fn[:-5])
                wd = bool(adv.get("withdrawn"))
                aliases = sorted({a.upper() for a in adv.get("aliases") or [] if CVE_RE.match(a.upper())})
                by_ghsa[gid] = (typ, wd, aliases)
                pub = (adv.get("published") or "")[:10]
                for a in aliases:
                    by_cve.setdefault(a, []).append((gid, typ, wd, pub))
    return by_cve, by_ghsa


def days_between(a, b):
    try:
        return (datetime.date.fromisoformat(b) - datetime.date.fromisoformat(a)).days
    except ValueError:
        return None


def classify(rec, by_cve, by_ghsa):
    holders = by_cve.get(rec["cve"], [])
    live = [h for h in holders if not h[2]]
    if any(h[1] == "reviewed" for h in live):
        cov = "REVIEWED"
    elif live:
        cov = "UNREVIEWED_ONLY"
    elif holders:
        cov = "WITHDRAWN_ONLY"
    else:
        cov = "NONE"
    ref = rec["repo_advs"][0]
    g = by_ghsa.get(ref["ghsa"])
    if g is None:
        ref_state = "NOT_GLOBAL"
    else:
        ref_state = "%s%s" % (g[0].upper(), "_WITHDRAWN" if g[1] else "")
    ref_live = g is not None and not g[1]
    ref_holds = "" if g is None else ("THIS" if rec["cve"] in g[2] else ("OTHER" if g[2] else "EMPTY"))
    other_live = sorted({h[0] for h in live if h[0] != ref["ghsa"]})
    dup = ref_live and bool(other_live)
    unrev_pubs = sorted(h[3] for h in live if h[1] == "unreviewed" and h[3])
    lag = days_between(rec["published"], unrev_pubs[0]) if (cov == "UNREVIEWED_ONLY" and unrev_pubs) else None
    return {"cve": rec["cve"], "arm": arm_of(rec), "source": rec["source"], "published": rec["published"],
            "nvd_status": rec["status"], "coverage": cov,
            "holders": ";".join("%s:%s%s" % (h[0], h[1], ":withdrawn" if h[2] else "") for h in holders),
            "ref_owner": ref["owner"], "ref_repo": ref["repo"], "ref_ghsa": ref["ghsa"],
            "ref_global_state": ref_state, "ref_holds": ref_holds, "other_live_holders": ";".join(other_live),
            "dup": "yes" if dup else "no", "unreviewed_lag_days": "" if lag is None else lag}


def uncovered(row):
    return row["coverage"] in ("NONE", "WITHDRAWN_ONLY")


# ---------- live sample ----------

def pick(rows, pred, n=SAMPLE_N, seed=SEED):
    pool = sorted((r for r in rows if pred(r)), key=lambda r: r["cve"])
    if len(pool) <= n:
        return pool
    return sorted(random.Random(seed).sample(pool, n), key=lambda r: r["cve"])


def sample_o(r):
    return r["arm"] == "O" and r["ref_global_state"] == "NOT_GLOBAL" and r["coverage"] == "UNREVIEWED_ONLY"


def sample_g(r):
    return r["arm"] == "G" and r["ref_global_state"] == "NOT_GLOBAL" and uncovered(r)


def read_sample(sample, get, pause=GH_PAUSE):
    out = []
    for r in sample:
        code, obj = get(GH_BY_CVE % r["cve"])
        if code == 200 and isinstance(obj, list):
            api = "EMPTY" if not obj else "FOUND:" + ";".join(sorted(norm_ghsa(a.get("ghsa_id") or "")
                                                                     for a in obj))
        else:
            api = "ERROR:%s" % code
        expect = "FOUND" if r["arm"] == "O" else "EMPTY"
        agree = "" if api.startswith("ERROR") else ("yes" if api.split(":")[0] == expect else "no")
        out.append({"cve": r["cve"], "arm": r["arm"], "source": r["source"], "coverage": r["coverage"],
                    "ref_ghsa": r["ref_ghsa"], "api_cve_lookup": api, "expected": expect, "agrees": agree})
        if pause:
            time.sleep(pause)
    return out


# ---------- verdicts ----------

def share(k, n):
    return [k, n, round(100.0 * k / n, 1) if n else None]


CLAIMS = {
    "Q1": "Arm O: <= 10% of CVEs have no live global advisory (NONE or WITHDRAWN_ONLY)",
    "Q2": "Arm O uncovered share is at least 25 percentage points lower than arm G's (same checkout)",
    "Q3": "NOT_GLOBAL stratum (cited repository advisory absent from the global DB): arm O covered share >= 80% "
          "AND arm G covered share <= 5%",
    "Q4": "Covered CVEs covered only by an unreviewed advisory: arm O >= 25% AND arm G <= 3%",
    "Q5": ">= 18 of the 20 live lookups agree with the checkout (arm O sample non-empty, arm G sample []); "
          "errors excluded, threshold scaled",
    "Q6": "Where the cited repository advisory is a live global record: arm O has a second live record for the "
          "CVE (DUP) in >= 5% of CVEs, and a higher DUP share than arm G",
}


def verdicts(rows, fetched, total, sample_rows):
    out = {}
    o = [r for r in rows if r["arm"] == "O"]
    g = [r for r in rows if r["arm"] == "G"]
    gate = total > 0 and fetched >= MIN_FETCH * total and len(o) >= MIN_ARM_O and len(g) >= MIN_ARM_O
    if not gate:
        for k in ("Q1", "Q2", "Q3", "Q4", "Q6"):
            out[k] = {"value": {"fetched": fetched, "total": total, "arm_O": len(o), "arm_G": len(g)},
                      "held": "INCONCLUSIVE (NVD fetch below 95%% or an arm below %d)" % MIN_ARM_O}
    else:
        uo = share(sum(1 for r in o if uncovered(r)), len(o))
        ug = share(sum(1 for r in g if uncovered(r)), len(g))
        out["Q1"] = {"value": uo, "held": "yes" if uo[2] <= 10.0 else "no"}
        out["Q2"] = {"value": {"O": uo, "G": ug}, "held": "yes" if ug[2] - uo[2] >= 25.0 else "no"}
        so = [r for r in o if r["ref_global_state"] == "NOT_GLOBAL"]
        sg = [r for r in g if r["ref_global_state"] == "NOT_GLOBAL"]
        co = share(sum(1 for r in so if not uncovered(r)), len(so))
        cg = share(sum(1 for r in sg if not uncovered(r)), len(sg))
        if len(so) < MIN_STRATUM or len(sg) < MIN_STRATUM:
            out["Q3"] = {"value": {"O": co, "G": cg}, "held": "INCONCLUSIVE (stratum below %d)" % MIN_STRATUM}
        else:
            out["Q3"] = {"value": {"O": co, "G": cg}, "held": "yes" if co[2] >= 80.0 and cg[2] <= 5.0 else "no"}
        vo = [r for r in o if not uncovered(r)]
        vg = [r for r in g if not uncovered(r)]
        ro = share(sum(1 for r in vo if r["coverage"] == "UNREVIEWED_ONLY"), len(vo))
        rg = share(sum(1 for r in vg if r["coverage"] == "UNREVIEWED_ONLY"), len(vg))
        ok = ro[2] is not None and rg[2] is not None and ro[2] >= 25.0 and rg[2] <= 3.0
        out["Q4"] = {"value": {"O": ro, "G": rg}, "held": "yes" if ok else "no"}
        lo = [r for r in o if r["ref_global_state"] in ("REVIEWED", "UNREVIEWED")]
        lg = [r for r in g if r["ref_global_state"] in ("REVIEWED", "UNREVIEWED")]
        do = share(sum(1 for r in lo if r["dup"] == "yes"), len(lo))
        dg = share(sum(1 for r in lg if r["dup"] == "yes"), len(lg))
        if len(lo) < MIN_STRATUM or len(lg) < MIN_STRATUM:
            out["Q6"] = {"value": {"O": do, "G": dg}, "held": "INCONCLUSIVE (stratum below %d)" % MIN_STRATUM}
        else:
            ok = do[2] >= 5.0 and do[2] > dg[2]
            out["Q6"] = {"value": {"O": do, "G": dg}, "held": "yes" if ok else "no"}
    read = [s for s in sample_rows if s["agrees"] in ("yes", "no")]
    if len(sample_rows) < 2 * SAMPLE_N or len(read) < 2 * SAMPLE_N - 4:
        out["Q5"] = {"value": [len(read), len(sample_rows)],
                     "held": "PENDING (sample too small or more than 4 errors; re-read by hand)"}
    else:
        k = sum(1 for s in read if s["agrees"] == "yes")
        need = 18.0 * len(read) / (2 * SAMPLE_N)
        out["Q5"] = {"value": share(k, len(read)), "held": "yes" if k >= need else "no"}
    for k in out:
        out[k]["claim"] = CLAIMS[k]
    return dict(sorted(out.items()))


def count_by(items, fn, top=None):
    out = {}
    for x in items:
        k = fn(x)
        out[k] = out.get(k, 0) + 1
    pairs = sorted(out.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return dict(pairs[:top] if top else pairs)


def descriptive(rows, per_source):
    o = [r for r in rows if r["arm"] == "O"]
    g = [r for r in rows if r["arm"] == "G"]
    src = {}
    for s, n in count_by(o, lambda r: r["source"], top=15).items():
        sub = [r for r in o if r["source"] == s]
        src[s] = {"n": n, "uncovered": sum(1 for r in sub if uncovered(r)),
                  "unreviewed_only": sum(1 for r in sub if r["coverage"] == "UNREVIEWED_ONLY")}
    lags = [r["unreviewed_lag_days"] for r in o if r["unreviewed_lag_days"] != ""]
    return {
        "nvd_records_by_source_top": dict(sorted(per_source.items(), key=lambda kv: (-kv[1], kv[0]))[:10]),
        "arm_sizes": {"O": len(o), "G": len(g)},
        "coverage": {"O": count_by(o, lambda r: r["coverage"]), "G": count_by(g, lambda r: r["coverage"])},
        "ref_global_state": {"O": count_by(o, lambda r: r["ref_global_state"]),
                             "G": count_by(g, lambda r: r["ref_global_state"])},
        "ref_holds": {"O": count_by(o, lambda r: r["ref_holds"] or "(not global)"),
                      "G": count_by(g, lambda r: r["ref_holds"] or "(not global)")},
        "arm_O_by_source": src,
        "arm_O_by_year": {y: {"n": sum(1 for r in o if r["published"][:4] == y),
                              "uncovered": sum(1 for r in o if r["published"][:4] == y and uncovered(r))}
                          for y in ("2025", "2026")},
        "arm_O_unreviewed_lag_days": {"n": len(lags), "median": statistics.median(lags) if lags else None,
                                      "max": max(lags) if lags else None,
                                      "note": "unreviewed GHSA 'published' minus NVD published, in days"},
        "top_repos_arm_O_uncovered": count_by([r for r in o if uncovered(r)],
                                              lambda r: "%s/%s" % (r["ref_owner"], r["ref_repo"]), top=15),
    }


# ---------- outputs ----------

ROW_COLS = ["cve", "arm", "source", "published", "nvd_status", "coverage", "holders", "ref_owner", "ref_repo",
            "ref_ghsa", "ref_global_state", "ref_holds", "other_live_holders", "dup", "unreviewed_lag_days"]
SAMPLE_COLS = ["cve", "arm", "source", "coverage", "ref_ghsa", "api_cve_lookup", "expected", "agrees"]


def write_csv(path, cols, items):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in items:
            w.writerow([r[c] for c in cols])


def write_outputs(out_dir, result, rows, sample_rows):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    write_csv(os.path.join(out_dir, "rows.csv"), ROW_COLS, rows)
    write_csv(os.path.join(out_dir, "sample.csv"), SAMPLE_COLS, sample_rows)
    lines = ["# S10: GitHub-CNA vs other-CNA CVEs that cite a repository advisory: job output", "",
             "advisory-database commit %s (%s); NVD read %s; %s of %s NVD records fetched (%s pages failed)." % (
                 result["db_commit"], result["db_commit_date"], result["read_at"], result["nvd_fetched"],
                 result["nvd_total"], result["nvd_pages_failed"]), "",
             "| Prediction | Claim | Value | Held |", "|---|---|---|---|"]
    for k, v in result["verdicts"].items():
        lines.append("| %s | %s | %s | %s |" % (k, v["claim"], json.dumps(v["value"]), v["held"]))
    lines += ["", "Descriptive: %s" % json.dumps(result["descriptive"])]
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def open_db(data_dir):
    """Use the shared checkout as it is (never fetch: other queued jobs read it). Clone only if missing."""
    root = os.path.join(data_dir, "advisory-database")
    if not os.path.isdir(os.path.join(root, ".git")):
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", DB_URL, root], check=True)
        subprocess.run(["git", "-C", root, "sparse-checkout", "set"] + SPARSE, check=True)
    sha = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    date = subprocess.run(["git", "-C", root, "log", "-1", "--format=%cI"], check=True,
                          capture_output=True, text=True).stdout.strip()
    return root, sha, date


def run(db_root, out_dir, get, db_commit="", db_date="", nvd_pause=NVD_PAUSE, gh_pause=GH_PAUSE, get_gh=None,
        chunks=None):
    get_gh = get_gh or get
    t = datetime.datetime.now(datetime.timezone.utc)
    recs, total, fetched, failed, per_source = fetch_nvd(get, chunks or month_chunks(), pause=nvd_pause)
    by_cve, by_ghsa = build_index({"reviewed": os.path.join(db_root, "advisories", "github-reviewed"),
                                   "unreviewed": os.path.join(db_root, "advisories", "unreviewed")})
    rows = [classify(r, by_cve, by_ghsa) for r in recs if in_window(r)]
    sample = pick(rows, sample_o) + pick(rows, sample_g)
    sample_rows = read_sample(sample, get_gh, pause=gh_pause)
    result = {"db_commit": db_commit, "db_commit_date": db_date, "read_at": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "nvd_total": total, "nvd_fetched": fetched, "nvd_pages_failed": failed,
              "global_advisories_indexed": len(by_ghsa), "window": list(WINDOW), "seed": SEED,
              "verdicts": verdicts(rows, fetched, total, sample_rows),
              "descriptive": descriptive(rows, per_source)}
    write_outputs(out_dir, result, rows, sample_rows)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    root, sha, date = open_db(args.data_dir)
    result = run(root, args.out_dir, http_get, db_commit=sha, db_date=date, get_gh=gh_get)
    print("done: %s of %s NVD records, arms %s; outputs in %s" % (
        result["nvd_fetched"], result["nvd_total"], result["descriptive"]["arm_sizes"], args.out_dir))


if __name__ == "__main__":
    main()
