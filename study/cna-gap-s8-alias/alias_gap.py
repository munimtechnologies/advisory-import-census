"""S8 follow-up: why do 78 GitHub-CNA CVEs cite a global GitHub advisory that does not list them?

Descriptive breakdown of one category S8 reported but did not predict (GLOBAL_WITHOUT_ALIAS: the CVE record's NVD
references cite a repository advisory that IS in the global Advisory Database, yet no live global advisory lists the
CVE). Five rows were looked at by hand before this was written (2026-11-05), so nothing here is a prediction.

For each input row (gwa_rows.csv, copied from S8's uncovered.csv) this reads the cited advisory's JSON from the local
github/advisory-database clone and the CVE record from CVE Services (cveawg.mitre.org, no account needed), and sorts
it into:
  MISSING_ALIAS       the cited advisory is live and lists no CVE at all
  HOLDS_OTHER_CVE     the cited advisory is live and lists a different CVE (bundled or related advisories)
  WITHDRAWN_ADVISORY  the cited advisory is withdrawn
  ADVISORY_NOT_FOUND  the cited advisory file is not in the clone
A row is a CANDIDATE for a one-line alias fix when it is MISSING_ALIAS, the CVE record is PUBLISHED by GitHub_M, the
record cites exactly one repository advisory (this one), and no other uncovered CVE cites the same advisory.

Outputs (--out-dir): alias_gap.csv, summary.json, ALIAS-GAP.md. Stdlib only. Apache-2.0.
Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request

CVEAWG = "https://cveawg.mitre.org/api/cve/%s"
UA = "advisory-import-census-alias-gap/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
REPO_ADV_RE = re.compile(
    r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/security/advisories/"
    r"(GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})", re.IGNORECASE)
PAUSE = 0.5
KINDS = ["MISSING_ALIAS", "HOLDS_OTHER_CVE", "WITHDRAWN_ADVISORY", "ADVISORY_NOT_FOUND"]
OUT_COLS = ["cve", "nvd_published", "ref_owner", "ref_repo", "ref_ghsa", "kind", "candidate", "bundle_size",
            "adv_aliases", "adv_published", "adv_modified", "adv_ecosystems", "cve_state", "cve_assigner",
            "cve_date_published", "cve_repo_advisories", "days_adv_to_cve", "title_matches_summary"]


def norm_ghsa(g):
    parts = g.split("-")
    return "GHSA-" + "-".join(p.lower() for p in parts[1:])


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
    ecos = sorted({((a.get("package") or {}).get("ecosystem") or "") for a in adv.get("affected") or []})
    return {"id": norm_ghsa(adv.get("id") or os.path.basename(path)[:-5]),
            "aliases": sorted({a.upper() for a in adv.get("aliases") or [] if CVE_RE.match(a.upper())}),
            "published": adv.get("published") or "", "modified": adv.get("modified") or "",
            "withdrawn": adv.get("withdrawn") or "", "summary": adv.get("summary") or "", "ecosystems": ecos}


def cve_facts(rec):
    """Fields needed from one CVE JSON 5 record (cveawg /api/cve/<id>)."""
    rec = rec or {}
    meta = rec.get("cveMetadata") or {}
    cont = rec.get("containers") or {}
    cna = cont.get("cna") or {}
    urls = [r.get("url") or "" for r in cna.get("references") or []]
    for adp in cont.get("adp") or []:
        urls += [r.get("url") or "" for r in adp.get("references") or []]
    advs = sorted({norm_ghsa(m.group(3)) for u in urls for m in [REPO_ADV_RE.search(u)] if m})
    return {"state": meta.get("state") or "", "assigner": meta.get("assignerShortName") or "",
            "date_published": meta.get("datePublished") or "", "title": cna.get("title") or "",
            "repo_advisories": advs}


def parse_ts(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        d = datetime.datetime.fromisoformat(s)
    except ValueError:
        try:
            d = datetime.datetime.fromisoformat(s[:19])
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d


def days_between(a, b):
    da, db = parse_ts(a), parse_ts(b)
    if da is None or db is None:
        return ""
    return int((db - da).total_seconds() // 86400)


def norm_text(s):
    return " ".join((s or "").lower().split())


def classify(row, adv, facts, bundle_size):
    ghsa = row["ref_ghsa"]
    if adv is None:
        kind = "ADVISORY_NOT_FOUND"
    elif adv["withdrawn"]:
        kind = "WITHDRAWN_ADVISORY"
    elif not adv["aliases"]:
        kind = "MISSING_ALIAS"
    else:
        kind = "HOLDS_OTHER_CVE"
    cand = (kind == "MISSING_ALIAS" and facts["state"] == "PUBLISHED" and facts["assigner"] == "GitHub_M"
            and facts["repo_advisories"] == [ghsa] and bundle_size == 1)
    adv = adv or {"aliases": [], "published": "", "modified": "", "ecosystems": [], "summary": ""}
    return {"cve": row["cve"], "nvd_published": row.get("published", ""), "ref_owner": row["ref_owner"],
            "ref_repo": row["ref_repo"], "ref_ghsa": ghsa, "kind": kind, "candidate": "yes" if cand else "no",
            "bundle_size": bundle_size, "adv_aliases": ";".join(adv["aliases"]),
            "adv_published": adv["published"], "adv_modified": adv["modified"],
            "adv_ecosystems": ";".join(e or "(empty)" for e in adv["ecosystems"]),
            "cve_state": facts["state"], "cve_assigner": facts["assigner"],
            "cve_date_published": facts["date_published"],
            "cve_repo_advisories": ";".join(facts["repo_advisories"]),
            "days_adv_to_cve": days_between(adv["published"], facts["date_published"]),
            "title_matches_summary": "yes" if facts["title"] and norm_text(facts["title"]) == norm_text(
                adv["summary"]) else "no"}


def read_rows(path):
    with open(path, encoding="utf-8", newline="") as f:
        rows = [r for r in csv.DictReader(f) if r.get("uncovered_kind") == "GLOBAL_WITHOUT_ALIAS"]
    for r in rows:
        r["ref_ghsa"] = norm_ghsa(r["ref_ghsa"])
        r["cve"] = r["cve"].upper()
    return rows


def run(rows, files, get, pause=PAUSE):
    bundles = {}
    for r in rows:
        bundles[r["ref_ghsa"]] = bundles.get(r["ref_ghsa"], 0) + 1
    out, errors = [], 0
    for r in rows:
        path = files.get(r["ref_ghsa"])
        adv = load_adv(path) if path else None
        code, rec = get(CVEAWG % r["cve"])
        if code != 200:
            errors += 1
        out.append(classify(r, adv, cve_facts(rec if code == 200 else None), bundles[r["ref_ghsa"]]))
        if pause:
            time.sleep(pause)
    return out, errors


def summarize(out, errors):
    kinds = {k: sum(1 for r in out if r["kind"] == k) for k in KINDS}
    miss = [r for r in out if r["kind"] == "MISSING_ALIAS"]
    gaps = sorted(r["days_adv_to_cve"] for r in miss if r["days_adv_to_cve"] != "")
    eco = {}
    for r in miss:
        for e in (r["adv_ecosystems"] or "(none)").split(";"):
            eco[e] = eco.get(e, 0) + 1
    return {"rows": len(out), "cveawg_errors": errors, "kinds": kinds,
            "candidates": sum(1 for r in out if r["candidate"] == "yes"),
            "missing_alias_cve_after_advisory": sum(1 for g in gaps if g > 0),
            "missing_alias_days_median": gaps[len(gaps) // 2] if gaps else None,
            "missing_alias_title_matches": sum(1 for r in miss if r["title_matches_summary"] == "yes"),
            "missing_alias_ecosystems": dict(sorted(eco.items(), key=lambda kv: (-kv[1], kv[0]))),
            "bundled_ghsas": sorted({r["ref_ghsa"] for r in out if r["bundle_size"] > 1})}


def write_outputs(out_dir, out, summary, meta):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "alias_gap.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(OUT_COLS)
        for r in out:
            w.writerow([r[c] for c in OUT_COLS])
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "summary": summary}, f, indent=1)
    lines = ["# S8 follow-up: GitHub-CNA CVEs whose cited global advisory does not list them (job output)", "",
             "Descriptive, not pre-registered. advisory-database HEAD %s; CVE records read %s." % (
                 meta.get("db_commit", ""), meta.get("read_at", "")), "",
             "| Kind | Rows |", "|---|---|"]
    for k in KINDS:
        lines.append("| %s | %s |" % (k, summary["kinds"][k]))
    lines += ["", "Candidates for a one-line alias fix: %s" % summary["candidates"], "",
              "Summary: %s" % json.dumps(summary)]
    with open(os.path.join(out_dir, "ALIAS-GAP.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def db_head(root):
    try:
        return subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], check=True, capture_output=True,
                              text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rows", required=True)
    ap.add_argument("--db-root", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    t = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = read_rows(args.rows)
    files = index_files(os.path.join(args.db_root, "advisories", "github-reviewed"))
    out, errors = run(rows, files, http_get)
    summary = summarize(out, errors)
    write_outputs(args.out_dir, out, summary, {"db_commit": db_head(args.db_root), "read_at": t,
                                               "reviewed_files_indexed": len(files)})
    print("done: %d rows, %d cveawg errors, kinds %s, %d candidates" % (
        len(out), errors, json.dumps(summary["kinds"]), summary["candidates"]))


if __name__ == "__main__":
    main()
