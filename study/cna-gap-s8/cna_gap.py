"""CVEs issued by GitHub's own CNA that GitHub's global Advisory Database does not carry (pre-registered study S8).

See PREREG.md. Population: every CVE whose NVD sourceIdentifier is security-advisories@github.com (GitHub's CNA,
`GitHub_M` in CVE records), published in NVD from 2025-01-01 to 2026-09-30 inclusive, not Rejected. For each CVE
this asks whether any live advisory in github/advisory-database (github-reviewed, or unreviewed 2025-2026) lists it
as an alias, and whether the repository advisory its CVE record cites (github.com/<owner>/<repo>/security/
advisories/GHSA-...) exists in the global database at all. A seeded sample of 20 uncovered CVEs is then read live
from the GitHub REST API (?cve_id= and the repository advisory's package ecosystems).

Outputs (--out-dir): results.json, RESULTS-job.md, cves.csv, uncovered.csv, sample.csv, named.csv.
Stdlib only. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime
import json
import os
import random
import re
import subprocess
import time
import urllib.error
import urllib.request

DB_URL = "https://github.com/github/advisory-database.git"
# Same sparse set as studies S3-S7, so the shared clone (data_key advisory-db-reviewed) is not re-checked-out.
SPARSE = ["advisories/github-reviewed", "advisories/unreviewed/2025", "advisories/unreviewed/2026"]
NVD_API = ("https://services.nvd.nist.gov/rest/json/cves/2.0?sourceIdentifier=security-advisories@github.com"
           "&resultsPerPage=%d&startIndex=%d")
NVD_ONE = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
GH_BY_CVE = "https://api.github.com/advisories?cve_id=%s"
GH_REPO_ADV = "https://api.github.com/repos/%s/%s/security-advisories/%s"
UA = "advisory-import-census-cna-gap/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
PAGE = 2000
NVD_PAUSE = 7.0          # NVD without a key: 5 requests per rolling 30 s
GH_PAUSE = 1.5
WINDOW = ("2025-01-01", "2026-09-30")
LATE = ("2026-10-01", "2026-12-31")   # reported, not predicted (review backlog)
SEED = 20261104
SAMPLE_N = 20
MIN_FETCH = 0.95
MIN_POP = 1000
SUPPORTED = {"rubygems", "npm", "pip", "maven", "nuget", "composer", "go", "rust", "erlang", "actions", "pub",
             "swift"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
REPO_ADV_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/security/advisories/"
    r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})", re.IGNORECASE)
GLOBAL_ADV_RE = re.compile(r"https?://github\.com/advisories/(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})",
                           re.IGNORECASE)
NAMED = {
    "github/advisory-database#10423": ["CVE-2026-108265", "CVE-2026-108266", "CVE-2026-108267", "CVE-2026-108268",
                                       "CVE-2026-108269", "CVE-2026-92701", "CVE-2026-92702", "CVE-2026-108362",
                                       "CVE-2026-33697"],
    "github/advisory-database#8851": ["CVE-2026-56670", "CVE-2026-56671", "CVE-2026-56672", "CVE-2026-56673"],
    "github/advisory-database#8831": ["CVE-2026-49481"],
    "github/advisory-database#10297": ["CVE-2026-92163"],
    "github/advisory-database#10402": ["CVE-2026-92704"],
    "github/advisory-database#9171": ["CVE-2026-63656"],
}


def norm_ghsa(g):
    parts = g.split("-")
    return "GHSA-" + "-".join(p.lower() for p in parts[1:])


# ---------- HTTP ----------

def http_get(url, timeout=120, tries=5, pause=10.0, accept="application/json"):
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


# ---------- NVD side ----------

def reduce_nvd(cve):
    """Fields S8 needs from one NVD 'cve' object."""
    refs = [r.get("url") or "" for r in cve.get("references") or []]
    repo_advs, seen = [], set()
    for u in refs:
        m = REPO_ADV_RE.search(u)
        if m:
            g = norm_ghsa(m.group(3))
            if g not in seen:
                seen.add(g)
                repo_advs.append({"owner": m.group(1), "repo": m.group(2), "ghsa": g})
    global_refs = sorted({norm_ghsa(m.group(1)) for u in refs for m in [GLOBAL_ADV_RE.search(u)] if m})
    return {"cve": (cve.get("id") or "").upper(), "source": cve.get("sourceIdentifier") or "",
            "published": (cve.get("published") or "")[:10], "status": cve.get("vulnStatus") or "",
            "repo_advs": repo_advs, "global_refs": global_refs}


def fetch_nvd(get, pause=NVD_PAUSE, page=PAGE):
    """All NVD records with GitHub's CNA as source. Returns (records, total_reported, pages_failed)."""
    out, start, total, failed = [], 0, None, 0
    while total is None or start < total:
        code, obj = get(NVD_API % (page, start))
        if code != 200 or not isinstance(obj, dict):
            failed += 1
            if total is None:
                break
            start += page
            continue
        total = int(obj.get("totalResults") or 0)
        vulns = obj.get("vulnerabilities") or []
        out.extend(reduce_nvd(v.get("cve") or {}) for v in vulns)
        if not vulns:
            break
        start += len(vulns)
        if pause and start < total:
            time.sleep(pause)
    uniq = {}
    for r in out:
        if r["cve"]:
            uniq[r["cve"]] = r
    return [uniq[k] for k in sorted(uniq)], (total or 0), failed


def in_window(rec, window=WINDOW):
    return window[0] <= rec["published"] <= window[1] and rec["status"].lower() != "rejected"


# ---------- global database side ----------

def build_index(roots):
    """roots: {"reviewed": path, "unreviewed": path}. Returns (by_cve, by_ghsa).
    by_cve[CVE] = list of (ghsa, type, withdrawn); by_ghsa[GHSA] = (type, withdrawn, aliases)."""
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
                for a in aliases:
                    by_cve.setdefault(a, []).append((gid, typ, wd))
    return by_cve, by_ghsa


def classify(rec, by_cve, by_ghsa):
    """Coverage of one CVE in the global database, and where its cited repository advisory stands."""
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
    ref = rec["repo_advs"][0] if rec["repo_advs"] else None
    ref_state = ""
    if ref:
        g = by_ghsa.get(ref["ghsa"])
        if g is None:
            ref_state = "NOT_GLOBAL"
        else:
            ref_state = "%s%s" % (g[0].upper(), "_WITHDRAWN" if g[1] else "")
    if cov in ("REVIEWED", "UNREVIEWED_ONLY"):
        kind = ""
    elif ref is None:
        kind = "NO_REPO_ADVISORY_REF"
    elif ref_state == "NOT_GLOBAL":
        kind = "REPO_ONLY"
    else:
        kind = "GLOBAL_WITHOUT_ALIAS"
    return {"cve": rec["cve"], "published": rec["published"], "nvd_status": rec["status"], "coverage": cov,
            "holders": ";".join("%s:%s%s" % (h[0], h[1], ":withdrawn" if h[2] else "") for h in holders),
            "ref_owner": ref["owner"] if ref else "", "ref_repo": ref["repo"] if ref else "",
            "ref_ghsa": ref["ghsa"] if ref else "", "ref_global_state": ref_state, "uncovered_kind": kind}


def uncovered(row):
    return row["coverage"] in ("NONE", "WITHDRAWN_ONLY")


# ---------- live sample ----------

def pick_sample(rows, n=SAMPLE_N, seed=SEED):
    pool = sorted((r for r in rows if uncovered(r)), key=lambda r: r["cve"])
    if len(pool) <= n:
        return pool
    return sorted(random.Random(seed).sample(pool, n), key=lambda r: r["cve"])


def ecosystems_of(adv):
    return sorted({((v.get("package") or {}).get("ecosystem") or "").lower()
                   for v in (adv.get("vulnerabilities") or [])})


def read_sample(sample, get, pause=GH_PAUSE):
    out = []
    for r in sample:
        code, obj = get(GH_BY_CVE % r["cve"])
        if code == 200 and isinstance(obj, list):
            api = "EMPTY" if not obj else "FOUND:" + ";".join(sorted(norm_ghsa(a.get("ghsa_id") or "")
                                                                     for a in obj))
        else:
            api = "ERROR:%s" % code
        if pause:
            time.sleep(pause)
        eco, rstate = "", ""
        if r["ref_ghsa"]:
            code2, adv = get(GH_REPO_ADV % (r["ref_owner"], r["ref_repo"], r["ref_ghsa"]))
            if code2 == 200 and isinstance(adv, dict):
                ecos = ecosystems_of(adv)
                eco = ";".join(e if e else "(empty)" for e in ecos) or "(none)"
                rstate = adv.get("state") or ""
            else:
                eco = "ERROR:%s" % code2
            if pause:
                time.sleep(pause)
        else:
            eco = "NO_REF"
        out.append({"cve": r["cve"], "ref_owner": r["ref_owner"], "ref_repo": r["ref_repo"],
                    "ref_ghsa": r["ref_ghsa"], "api_cve_lookup": api, "repo_advisory_state": rstate,
                    "repo_advisory_ecosystems": eco})
    return out


def unsupported(eco_field):
    """True if a repository advisory lists no package in a supported registry ('' and 'other' are not)."""
    if eco_field.startswith("ERROR") or eco_field == "NO_REF":
        return None
    ecos = [e for e in eco_field.split(";") if e]
    return not any(e in SUPPORTED for e in ecos)


# ---------- verdicts ----------

def share(k, n):
    return [k, n, round(100.0 * k / n, 1) if n else None]


CLAIMS = {
    "P1": "5% <= share of population CVEs with no live global advisory (NONE or WITHDRAWN_ONLY) <= 30%",
    "P2": "<= 3% of covered population CVEs are covered only by an unreviewed advisory",
    "P3": ">= 90% of uncovered CVEs are REPO_ONLY (cited repository advisory absent from the global database)",
    "P4": "uncovered share for CVEs published 2026-01-01..2026-09-30 is higher than for 2025",
    "P5": ">= 18 of the 20 sampled uncovered CVEs return [] from GET /advisories?cve_id= (errors excluded)",
    "P6": ">= 14 of the 20 sampled uncovered CVEs cite a repository advisory with no package in a supported "
          "registry (errors excluded; scaled to the CVEs read)",
}


def verdicts(rows, fetched, total, sample_rows):
    out = {}
    if total == 0 or fetched < MIN_FETCH * total or len(rows) < MIN_POP:
        for k in ("P1", "P2", "P3", "P4"):
            out[k] = {"value": [fetched, total, len(rows)],
                      "held": "INCONCLUSIVE (NVD fetch below 95% or population below 1000)"}
    else:
        unc = [r for r in rows if uncovered(r)]
        cov = [r for r in rows if not uncovered(r)]
        v = share(len(unc), len(rows))
        out["P1"] = {"value": v, "held": "yes" if 5.0 <= v[2] <= 30.0 else "no"}
        v = share(sum(1 for r in cov if r["coverage"] == "UNREVIEWED_ONLY"), len(cov))
        out["P2"] = {"value": v, "held": "yes" if v[2] is not None and v[2] <= 3.0 else "no"}
        v = share(sum(1 for r in unc if r["uncovered_kind"] == "REPO_ONLY"), len(unc))
        out["P3"] = {"value": v, "held": "yes" if v[2] is not None and v[2] >= 90.0 else "no"}
        y25 = [r for r in rows if r["published"] < "2026-01-01"]
        y26 = [r for r in rows if r["published"] >= "2026-01-01"]
        a = share(sum(1 for r in y25 if uncovered(r)), len(y25))
        b = share(sum(1 for r in y26 if uncovered(r)), len(y26))
        ok = a[2] is not None and b[2] is not None and b[2] > a[2]
        out["P4"] = {"value": {"2025": a, "2026": b}, "held": "yes" if ok else "no"}
    read5 = [s for s in sample_rows if not s["api_cve_lookup"].startswith("ERROR")]
    if len(sample_rows) < SAMPLE_N or len(read5) < SAMPLE_N - 4:
        out["P5"] = {"value": [len(read5), len(sample_rows)],
                     "held": "PENDING (sample too small or more than 4 errors; re-read by hand)"}
    else:
        k = sum(1 for s in read5 if s["api_cve_lookup"] == "EMPTY")
        need = 18.0 * len(read5) / SAMPLE_N
        out["P5"] = {"value": share(k, len(read5)), "held": "yes" if k >= need else "no"}
    flags = [unsupported(s["repo_advisory_ecosystems"]) for s in sample_rows]
    read6 = [f for f in flags if f is not None]
    if len(sample_rows) < SAMPLE_N or len(read6) < SAMPLE_N - 4:
        out["P6"] = {"value": [len(read6), len(sample_rows)],
                     "held": "PENDING (sample too small or more than 4 errors; re-read by hand)"}
    else:
        k = sum(1 for f in read6 if f)
        need = 14.0 * len(read6) / SAMPLE_N
        out["P6"] = {"value": share(k, len(read6)), "held": "yes" if k >= need else "no"}
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


def descriptive(all_recs, rows, late_rows):
    unc = [r for r in rows if uncovered(r)]
    return {
        "nvd_records": len(all_recs), "population": len(rows),
        "coverage": count_by(rows, lambda r: r["coverage"]),
        "uncovered_kind": count_by(unc, lambda r: r["uncovered_kind"]),
        "ref_global_state_of_uncovered": count_by(unc, lambda r: r["ref_global_state"] or "(no ref)"),
        "uncovered_by_month": dict(sorted(count_by(unc, lambda r: r["published"][:7]).items())),
        "population_by_month": dict(sorted(count_by(rows, lambda r: r["published"][:7]).items())),
        "top_repos_uncovered": count_by(unc, lambda r: "%s/%s" % (r["ref_owner"], r["ref_repo"])
                                        if r["ref_owner"] else "(no ref)", top=25),
        "nvd_status_of_uncovered": count_by(unc, lambda r: r["nvd_status"]),
        "late_window_2026_10": {"population": len(late_rows),
                                "coverage": count_by(late_rows, lambda r: r["coverage"])},
    }


def named_cases(recs_by_cve, by_cve, by_ghsa, get, pause=NVD_PAUSE):
    out = []
    for issue, cves in NAMED.items():
        for c in cves:
            rec = recs_by_cve.get(c)
            if rec is None:
                code, obj = get(NVD_ONE % c)
                vulns = (obj or {}).get("vulnerabilities") or [] if code == 200 else []
                rec = reduce_nvd(vulns[0]["cve"]) if vulns else None
                if pause:
                    time.sleep(pause)
            if rec is None:
                out.append({"issue": issue, "cve": c, "in_nvd": False, "source": "", "published": "",
                            "coverage": "", "ref_ghsa": "", "ref_global_state": "", "uncovered_kind": ""})
                continue
            row = classify(rec, by_cve, by_ghsa)
            out.append({"issue": issue, "cve": c, "in_nvd": True, "source": rec["source"],
                        "published": rec["published"], "coverage": row["coverage"], "ref_ghsa": row["ref_ghsa"],
                        "ref_global_state": row["ref_global_state"], "uncovered_kind": row["uncovered_kind"]})
    return out


# ---------- outputs ----------

ROW_COLS = ["cve", "published", "nvd_status", "coverage", "holders", "ref_owner", "ref_repo", "ref_ghsa",
            "ref_global_state", "uncovered_kind"]
SAMPLE_COLS = ["cve", "ref_owner", "ref_repo", "ref_ghsa", "api_cve_lookup", "repo_advisory_state",
               "repo_advisory_ecosystems"]
NAMED_COLS = ["issue", "cve", "in_nvd", "source", "published", "coverage", "ref_ghsa", "ref_global_state",
              "uncovered_kind"]


def write_csv(path, cols, items):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in items:
            w.writerow([r[c] for c in cols])


def write_outputs(out_dir, result, rows, sample_rows, named):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    write_csv(os.path.join(out_dir, "cves.csv"), ROW_COLS, rows)
    write_csv(os.path.join(out_dir, "uncovered.csv"), ROW_COLS, [r for r in rows if uncovered(r)])
    write_csv(os.path.join(out_dir, "sample.csv"), SAMPLE_COLS, sample_rows)
    write_csv(os.path.join(out_dir, "named.csv"), NAMED_COLS, named)
    lines = ["# GitHub-CNA CVEs missing from the global Advisory Database (S8): job output", "",
             "advisory-database commit %s (%s); NVD read %s; %s of %s NVD records fetched." % (
                 result["db_commit"], result["db_commit_date"], result["read_at"], result["nvd_fetched"],
                 result["nvd_total"]), "",
             "| Prediction | Claim | Value | Held |", "|---|---|---|---|"]
    for k, v in result["verdicts"].items():
        lines.append("| %s | %s | %s | %s |" % (k, v["claim"], json.dumps(v["value"]), v["held"]))
    lines += ["", "Descriptive: %s" % json.dumps(result["descriptive"])]
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def sync_db(data_dir):
    root = os.path.join(data_dir, "advisory-database")
    if not os.path.isdir(os.path.join(root, ".git")):
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", DB_URL, root], check=True)
    else:
        subprocess.run(["git", "-C", root, "fetch", "--depth", "1", "origin", "main"], check=True)
        subprocess.run(["git", "-C", root, "reset", "--hard", "FETCH_HEAD"], check=True)
    subprocess.run(["git", "-C", root, "sparse-checkout", "set"] + SPARSE, check=True)
    sha = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    date = subprocess.run(["git", "-C", root, "log", "-1", "--format=%cI"], check=True,
                          capture_output=True, text=True).stdout.strip()
    return root, sha, date


def gh_get(url):
    """GitHub REST API read: fewer, shorter retries (60 anonymous calls an hour per IP)."""
    return http_get(url, timeout=60, tries=2, pause=5.0, accept="application/vnd.github+json")


def run(db_root, out_dir, get, db_commit="", db_date="", nvd_pause=NVD_PAUSE, gh_pause=GH_PAUSE, get_gh=None):
    get_gh = get_gh or get
    t = datetime.datetime.now(datetime.timezone.utc)
    recs, total, failed = fetch_nvd(get, pause=nvd_pause)
    by_cve, by_ghsa = build_index({"reviewed": os.path.join(db_root, "advisories", "github-reviewed"),
                                   "unreviewed": os.path.join(db_root, "advisories", "unreviewed")})
    rows = [classify(r, by_cve, by_ghsa) for r in recs if in_window(r)]
    late = [classify(r, by_cve, by_ghsa) for r in recs if in_window(r, LATE)]
    sample_rows = read_sample(pick_sample(rows), get_gh, pause=gh_pause)
    named = named_cases({r["cve"]: r for r in recs}, by_cve, by_ghsa, get, pause=nvd_pause)
    result = {"db_commit": db_commit, "db_commit_date": db_date, "read_at": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "nvd_total": total, "nvd_fetched": len(recs), "nvd_pages_failed": failed,
              "global_advisories_indexed": len(by_ghsa), "window": list(WINDOW), "seed": SEED,
              "verdicts": verdicts(rows, len(recs), total, sample_rows),
              "descriptive": descriptive(recs, rows, late)}
    write_outputs(out_dir, result, rows, sample_rows, named)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    root, sha, date = sync_db(args.data_dir)
    result = run(root, args.out_dir, http_get, db_commit=sha, db_date=date, get_gh=gh_get)
    print("done: %s of %s NVD records, %s global advisories indexed; outputs in %s" % (
        result["nvd_fetched"], result["nvd_total"], result["global_advisories_indexed"], args.out_dir))


if __name__ == "__main__":
    main()
