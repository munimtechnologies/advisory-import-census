"""CVE aliases on GitHub-reviewed advisories that the CVE List does not have (pre-registered study S7).

See PREREG.md. Population: s6_missing.csv, the alias rows that study S6 found absent from the CVE Program's bulk
CVE List (release cve_2026-11-01_1700Z). For each distinct CVE ID this reads its state and owning CNA from the
public CVE Services endpoint /api/cve-id/ (RESERVED, PUBLISHED, REJECTED, or 404 = NOT_FOUND), adds the CVE record
where one exists, re-reads each advisory from github/advisory-database, and for NOT_FOUND IDs lists typo
candidates: CVE IDs the advisory itself mentions that are within edit distance 2 and PUBLISHED.

Outputs (--out-dir): results.json, RESULTS-job.md, aliases.csv, candidates.csv, grading_sample.csv.
The job prints no counts or verdicts (P6 is graded by hand first).
Stdlib only. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.
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

DB_URL = "https://github.com/github/advisory-database.git"
# Same sparse set as studies S3-S6, so the shared clone is not re-checked-out.
SPARSE = ["advisories/github-reviewed", "advisories/unreviewed/2025", "advisories/unreviewed/2026"]
CVE_ID_API = "https://cveawg.mitre.org/api/cve-id/%s"
CVE_API = "https://cveawg.mitre.org/api/cve/%s"
UA = "advisory-import-census-reserved-alias/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
POPULATION = "s6_missing.csv"
POP_COLS = ["reviewed", "cve", "reviewed_published"]
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CVE_FIND = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
STATES = ("PUBLISHED", "RESERVED", "REJECTED", "NOT_FOUND", "ERROR")
MAX_DIST = 2
AGE_DAYS = 180
ERROR_LIMIT = 0.10
MIN_NOT_FOUND = 3
PAUSE = 0.4


def squash(text, n):
    return " ".join((text or "").split())[:n]


# ---------- population ----------

def load_population(path):
    with open(path, encoding="utf-8", newline="") as f:
        rd = csv.DictReader(f)
        if rd.fieldnames != POP_COLS:
            raise ValueError("unexpected columns %r" % rd.fieldnames)
        rows = [dict(r) for r in rd]
    for r in rows:
        if not CVE_RE.match(r["cve"]) or not r["reviewed"].startswith("GHSA-"):
            raise ValueError("bad population row %r" % r)
    return rows


# ---------- HTTP ----------

def http_get(url, timeout=60, tries=3, pause=2.0):
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


# ---------- CVE state ----------

def id_state(cve, get):
    """State of a CVE ID from /api/cve-id/. get(url) -> (status, obj)."""
    code, obj = get(CVE_ID_API % cve)
    if code == 200 and isinstance(obj, dict) and obj.get("state"):
        st = str(obj["state"]).upper()
        return {"state": st if st in STATES else "ERROR", "owning_cna": obj.get("owning_cna") or "",
                "id_updated": (obj.get("dateUpdated") or "")[:19], "http": code}
    if code == 404:
        return {"state": "NOT_FOUND", "owning_cna": "", "id_updated": "", "http": code}
    return {"state": "ERROR", "owning_cna": "", "id_updated": "", "http": code}


def parse_record(obj):
    meta = obj.get("cveMetadata") or {}
    cna = (obj.get("containers") or {}).get("cna") or {}
    desc = " ".join(d.get("value") or "" for d in cna.get("descriptions") or [])
    rej = " ".join(d.get("value") or "" for d in cna.get("rejectedReasons") or [])
    return {"record_state": meta.get("state") or "", "assigner": meta.get("assignerShortName") or "",
            "date_published": (meta.get("datePublished") or "")[:19],
            "date_rejected": (meta.get("dateRejected") or "")[:19],
            "reason": squash(rej, 300), "text": squash(desc, 400)}


def record(cve, get):
    """CVE record fields, or {} if there is no record."""
    code, obj = get(CVE_API % cve)
    if code == 200 and isinstance(obj, dict):
        return parse_record(obj)
    return {}


# ---------- advisories ----------

def mentioned_cves(adv):
    """Upper-cased CVE IDs mentioned in an OSV-format advisory: aliases, summary, details, reference URLs."""
    found = set(a.upper() for a in adv.get("aliases") or [] if CVE_RE.match(a.upper()))
    for text in (adv.get("summary") or "", adv.get("details") or ""):
        found.update(m.upper() for m in CVE_FIND.findall(text))
    for r in adv.get("references") or []:
        found.update(m.upper() for m in CVE_FIND.findall(r.get("url") or ""))
    return found


def reduce_advisory(adv):
    pkgs = sorted({"%s:%s" % ((a.get("package") or {}).get("ecosystem") or "", (a.get("package") or {})["name"])
                   for a in adv.get("affected") or [] if (a.get("package") or {}).get("name")})
    return {"id": adv["id"], "withdrawn": bool(adv.get("withdrawn")),
            "published": (adv.get("published") or "")[:10], "modified": (adv.get("modified") or "")[:19],
            "aliases": sorted(a for a in adv.get("aliases") or [] if CVE_RE.match(a)),
            "mentioned": sorted(mentioned_cves(adv)), "packages": pkgs,
            "summary": squash(adv.get("summary"), 300), "details": squash(adv.get("details"), 600)}


def load_selected(reviewed_root, wanted):
    """Reduced advisories for the GHSA IDs in `wanted`, found by folder name under github-reviewed/."""
    out = {}
    for dirpath, dirs, files in os.walk(reviewed_root):
        name = os.path.basename(dirpath)
        if name in wanted and name + ".json" in files:
            with open(os.path.join(dirpath, name + ".json"), encoding="utf-8") as fh:
                out[name] = reduce_advisory(json.load(fh))
            dirs[:] = []
    return out


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


# ---------- typo candidates ----------

def edit_distance(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def typo_candidates(alias, advisory):
    """CVE IDs the advisory mentions, other than the alias, within MAX_DIST edits of it."""
    if not advisory:
        return []
    return sorted(c for c in advisory["mentioned"] if c != alias and edit_distance(c, alias) <= MAX_DIST)


# ---------- census ----------

def analyse(population, advisories, get, read_date, pause=0.0):
    """Per-ID table, candidate table and grading sample. get(url) -> (status, obj)."""
    holders = {}
    for r in population:
        holders.setdefault(r["cve"], []).append(r["reviewed"])
    states = {}
    for cve in sorted(holders):
        st = id_state(cve, get)
        if st["state"] in ("PUBLISHED", "REJECTED"):
            st.update(record(cve, get))
        states[cve] = st
        if pause:
            time.sleep(pause)
    ids, cands = [], []
    for cve in sorted(holders):
        st = states[cve]
        advs = [advisories.get(g) for g in holders[cve]]
        published = sorted(a["published"] for a in advs if a and a["published"]) or \
            sorted(r["reviewed_published"] for r in population if r["cve"] == cve)
        earliest = published[0] if published else ""
        age = None
        if earliest:
            age = (read_date - datetime.date.fromisoformat(earliest[:10])).days
        still = [a for a in advs if a and not a["withdrawn"] and cve in a["aliases"]]
        other_aliases = sorted({x for a in still for x in a["aliases"] if x != cve})
        row = {"cve": cve, "reviewed": ";".join(holders[cve]), "state": st["state"],
               "owning_cna": st["owning_cna"], "id_updated": st["id_updated"], "http": st["http"],
               "has_record": bool(st.get("record_state")), "date_published": st.get("date_published", ""),
               "date_rejected": st.get("date_rejected", ""), "reason": st.get("reason", ""),
               "earliest_advisory_published": earliest, "advisory_age_days": age,
               "still_on_live_advisory": bool(still), "other_aliases": ";".join(other_aliases),
               "only_alias": bool(still) and not other_aliases, "candidates": ""}
        if st["state"] == "NOT_FOUND":
            found = []
            for g in holders[cve]:
                for c in typo_candidates(cve, advisories.get(g)):
                    cst = id_state(c, get)
                    if pause:
                        time.sleep(pause)
                    if cst["state"] != "PUBLISHED":
                        continue
                    rec = record(c, get)
                    adv = advisories[g]
                    found.append({"cve": cve, "reviewed": g, "candidate": c, "distance": edit_distance(c, cve),
                                  "candidate_is_alias": c in adv["aliases"],
                                  "candidate_assigner": rec.get("assigner", ""),
                                  "advisory_summary": adv["summary"], "advisory_details": adv["details"],
                                  "candidate_text": rec.get("text", "")})
            row["candidates"] = ";".join(sorted({x["candidate"] for x in found}))
            cands.extend(found)
        ids.append(row)
    return ids, cands


def rate(k, n, threshold, at_most=False):
    if n == 0:
        return {"value": [k, n, None], "held": "n/a"}
    pct = round(100.0 * k / n, 1)
    ok = pct <= threshold if at_most else pct >= threshold
    return {"value": [k, n, pct], "held": "yes" if ok else "no"}


CLAIMS = {
    "P1": ">= 50% of the distinct IDs whose state was read are RESERVED",
    "P2": ">= 10% of the distinct IDs whose state was read are REJECTED",
    "P3": ">= 3 distinct IDs are NOT_FOUND (never allocated)",
    "P4": ">= 50% of RESERVED IDs sit on a reviewed advisory published at least 180 days before the read date",
    "P5": "GitHub_M owns at most 10% of the RESERVED IDs",
    "P6": ">= 50% of NOT_FOUND IDs have a typo candidate graded SAME by hand (graded from grading_sample.csv)",
}


def verdicts(ids):
    read = [r for r in ids if r["state"] != "ERROR"]
    n_err = len(ids) - len(read)
    by = {s: [r for r in read if r["state"] == s] for s in STATES}
    out = {}
    if not ids or n_err > ERROR_LIMIT * len(ids):
        for k in ("P1", "P2", "P3", "P4", "P5"):
            out[k] = {"value": [n_err, len(ids)], "held": "INCONCLUSIVE (more than 10% ERROR)"}
    else:
        out["P1"] = rate(len(by["RESERVED"]), len(read), 50.0)
        out["P2"] = rate(len(by["REJECTED"]), len(read), 10.0)
        out["P3"] = {"value": len(by["NOT_FOUND"]), "held": "yes" if len(by["NOT_FOUND"]) >= 3 else "no"}
        res = by["RESERVED"]
        out["P4"] = rate(sum(1 for r in res if r["advisory_age_days"] is not None
                             and r["advisory_age_days"] >= AGE_DAYS), len(res), 50.0)
        out["P5"] = rate(sum(1 for r in res if r["owning_cna"].lower() == "github_m"), len(res), 10.0,
                         at_most=True)
    nf = [r for r in ids if r["state"] == "NOT_FOUND"]
    if len(nf) < MIN_NOT_FOUND:
        out["P6"] = {"value": len(nf), "held": "INCONCLUSIVE_UNDERPOWERED (fewer than 3 NOT_FOUND IDs)"}
    else:
        out["P6"] = {"value": None, "held": "graded by hand after the run"}
    for k in out:
        out[k]["claim"] = CLAIMS[k]
    return dict(sorted(out.items()))


def count_by(items, fn):
    out = {}
    for x in items:
        k = fn(x)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def descriptive(population, ids, cands):
    return {
        "population_rows": len(population), "distinct_ids": len(ids),
        "states": count_by(ids, lambda r: r["state"]),
        "owning_cna_by_state": {s: count_by([r for r in ids if r["state"] == s], lambda r: r["owning_cna"])
                                for s in STATES if any(r["state"] == s for r in ids)},
        "rejected_with_record": sum(1 for r in ids if r["state"] == "REJECTED" and r["has_record"]),
        "rejected_only_alias": sum(1 for r in ids if r["state"] == "REJECTED" and r["only_alias"]),
        "published_after_snapshot": sum(1 for r in ids if r["state"] == "PUBLISHED"
                                        and r["date_published"] >= "2026-11-01T17"),
        "not_on_live_advisory_now": sum(1 for r in ids if not r["still_on_live_advisory"]),
        "not_found_with_candidate": len({c["cve"] for c in cands}),
        "candidate_pairs": len(cands),
    }


# ---------- outputs ----------

ID_COLS = ["cve", "reviewed", "state", "owning_cna", "id_updated", "http", "has_record", "date_published",
           "date_rejected", "reason", "earliest_advisory_published", "advisory_age_days",
           "still_on_live_advisory", "other_aliases", "only_alias", "candidates"]
CAND_COLS = ["cve", "reviewed", "candidate", "distance", "candidate_is_alias", "candidate_assigner",
             "advisory_summary", "advisory_details", "candidate_text"]
# The grading sample carries no states, counts or distances: the two IDs and the two texts only.
SAMPLE_COLS = ["cve", "reviewed", "candidate", "advisory_summary", "advisory_details", "candidate_text"]


def write_csv(path, cols, items, extra=None):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols + ([extra] if extra else []))
        for r in items:
            w.writerow([r[c] for c in cols] + ([""] if extra else []))


def write_outputs(out_dir, result, ids, cands):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    write_csv(os.path.join(out_dir, "aliases.csv"), ID_COLS, ids)
    write_csv(os.path.join(out_dir, "candidates.csv"), CAND_COLS, cands)
    write_csv(os.path.join(out_dir, "grading_sample.csv"), SAMPLE_COLS, cands, extra="grade")
    lines = ["# Reserved / rejected / never-allocated CVE aliases S7: job output", "",
             "advisory-database commit %s (%s); CVE Services read %s." % (
                 result["db_commit"], result["db_commit_date"], result["read_at"]), "",
             "| Prediction | Claim | Value | Held |", "|---|---|---|---|"]
    for k, v in result["verdicts"].items():
        lines.append("| %s | %s | %s | %s |" % (k, v["claim"], json.dumps(v["value"]), v["held"]))
    lines += ["", "Descriptive: %s" % json.dumps(result["descriptive"])]
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def run(population_path, reviewed_root, out_dir, get, db_commit="", db_date="", pause=0.0):
    population = load_population(population_path)
    wanted = {r["reviewed"] for r in population}
    advisories = load_selected(reviewed_root, wanted)
    t = now()
    ids, cands = analyse(population, advisories, get, t.date(), pause=pause)
    result = {"db_commit": db_commit, "db_commit_date": db_date, "read_at": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
              "advisories_found": len(advisories), "verdicts": verdicts(ids),
              "descriptive": descriptive(population, ids, cands)}
    write_outputs(out_dir, result, ids, cands)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--population", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), POPULATION))
    args = ap.parse_args()
    root, sha, date = sync_db(args.data_dir)
    run(args.population, os.path.join(root, "advisories", "github-reviewed"), args.out_dir, http_get,
        db_commit=sha, db_date=date, pause=PAUSE)
    # Print no counts or verdicts: P6 is graded from grading_sample.csv before anyone reads them.
    print("done: outputs written to %s" % args.out_dir)


if __name__ == "__main__":
    main()
