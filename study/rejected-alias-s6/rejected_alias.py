"""Rejected-alias census (pre-registered study S6, see PREREG.md).

Question: how many live GitHub-reviewed advisories still carry a CVE alias whose CVE record its CNA
has REJECTED, and how often does a PUBLISHED CVE for the same flaw exist elsewhere (named in the
rejection reason, or held by an unreviewed GHSA that links the reviewed one) that a lookup by CVE
does not connect to the reviewed advisory's packages?

Data:
  - github/advisory-database, advisories/github-reviewed plus advisories/unreviewed/2025 and /2026
    (sparse, blob-filtered git clone, the same cache as studies S1-S5). Commit SHA and date recorded.
  - The CVE Program's bulk CVE List release (CVEProject/cvelistV5, latest release asset
    *_all_CVEs_at_midnight.zip.zip), downloaded to a temporary folder and deleted after reading.
    Release tag recorded. Records not in the list (RESERVED or never assigned) count as MISSING.

Outputs (--out-dir): results.json, RESULTS-job.md, rows.csv, replacements.csv, mismatch.csv,
missing.csv, grading_sample.csv. The job prints no counts or verdicts (P6 is graded by hand first).
Stdlib only. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

DB_URL = "https://github.com/github/advisory-database.git"
SPARSE = ["advisories/github-reviewed", "advisories/unreviewed/2025", "advisories/unreviewed/2026"]
RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
ASSET_SUFFIX = "_all_CVEs_at_midnight.zip.zip"
UA = "advisory-import-census-rejected-alias/1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
SEED = 20261103
SAMPLE_N = 20
MIN_ROWS = 5
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CVE_FIND = re.compile(r"CVE-\d{4}-\d{4,}")
GHSA_FIND = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)
CVE_FILE = re.compile(r"(?:^|/)(CVE-\d{4}-\d{4,})\.json$")


def norm_ghsa(s):
    return "GHSA-" + s[5:].lower()


def squash(text, n):
    return " ".join((text or "").split())[:n]


# ---------- advisory records ----------

def parse_record(obj, keep_text=True):
    """Reduce one OSV-format GHSA record to the fields this study needs."""
    pkgs = set()
    for a in obj.get("affected") or []:
        p = a.get("package") or {}
        if p.get("name"):
            pkgs.add("%s:%s" % (p.get("ecosystem") or "", p["name"]))
    gid = obj["id"]
    linked = set()
    for r in obj.get("references") or []:
        for m in GHSA_FIND.findall(r.get("url") or ""):
            g = norm_ghsa(m)
            if g != gid:
                linked.add(g)
    out = {
        "id": gid,
        "cves": sorted(x for x in obj.get("aliases") or [] if CVE_RE.match(x)),
        "withdrawn": bool(obj.get("withdrawn")),
        "published": (obj.get("published") or "")[:10],
        "modified": (obj.get("modified") or "")[:19],
        "linked": sorted(linked),
        "packages": sorted(pkgs),
    }
    if keep_text:
        out["summary"] = squash(obj.get("summary"), 300)
        out["details"] = squash(obj.get("details"), 400)
    return out


# ---------- CVE records ----------

def parse_cve(obj):
    """Reduce a CVE JSON 5 record to state, assigner, dates, cited GHSAs, reason and text."""
    meta = obj.get("cveMetadata") or {}
    cna = (obj.get("containers") or {}).get("cna") or {}
    desc = " ".join(d.get("value") or "" for d in cna.get("descriptions") or [])
    rej = " ".join(d.get("value") or "" for d in cna.get("rejectedReasons") or [])
    ghsas = set()
    for r in cna.get("references") or []:
        for m in GHSA_FIND.findall(r.get("url") or ""):
            ghsas.add(norm_ghsa(m))
    return {
        "id": meta.get("cveId") or "",
        "state": meta.get("state") or "",
        "assigner": meta.get("assignerShortName") or "",
        "published": (meta.get("datePublished") or "")[:19],
        "rejected": (meta.get("dateRejected") or "")[:19],
        "ghsas": sorted(ghsas),
        "reason": squash(rej, 300),
        "text": squash(desc, 400),
    }


def reason_class(reason, self_id=""):
    """Coarse class of a rejection reason: duplicate, error, not_vuln, unspecified or other."""
    low = (reason or "").lower()
    others = [c for c in CVE_FIND.findall(reason or "") if c != self_id]
    if "duplicate" in low or others:
        return "duplicate"
    if "in error" in low or "assigned by mistake" in low or "erroneous" in low:
        return "error"
    if ("not a vulnerab" in low or "not a security" in low or "no vulnerab" in low
            or "disput" in low or "not considered a vulnerab" in low):
        return "not_vuln"
    if not low.strip() or re.fullmatch(r"(\*\* ?reject ?\*\* ?)?this cve id has been rejected"
                                       r"( or withdrawn by its cve numbering authority)?\.?", low.strip()):
        return "unspecified"
    return "other"


class CveList:
    """Random access to CVE records inside the bulk CVE List zip (a zip, possibly holding a zip)."""

    def __init__(self, path, workdir):
        self._tmp = None
        zf = zipfile.ZipFile(path)
        names = zf.namelist()
        if not any(CVE_FILE.search(n) for n in names):
            inner = [n for n in names if n.lower().endswith(".zip")]
            if not inner:
                raise ValueError("no CVE records and no inner zip in %s" % path)
            self._tmp = os.path.join(workdir, "inner-cves.zip")
            with zf.open(inner[0]) as src, open(self._tmp, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 20)
            zf.close()
            zf = zipfile.ZipFile(self._tmp)
            names = zf.namelist()
        self.zf = zf
        self.index = {}
        for n in names:
            m = CVE_FILE.search(n)
            if m:
                self.index[m.group(1)] = n
        self.cache = {}

    def uses_inner(self):
        return self._tmp is not None

    def get(self, cve):
        """Parsed record, or None if the CVE is not in the list."""
        if cve in self.cache:
            return self.cache[cve]
        name = self.index.get(cve)
        rec = None
        if name:
            with self.zf.open(name) as fh:
                rec = parse_cve(json.loads(fh.read().decode("utf-8-sig")))
        self.cache[cve] = rec
        return rec

    def close(self):
        self.zf.close()
        if self._tmp and os.path.exists(self._tmp):
            os.remove(self._tmp)


# ---------- census ----------

def analyse(reviewed, unreviewed, lookup):
    """Rows for live reviewed GHSAs holding a REJECTED CVE alias. lookup(cve) -> parsed record or None."""
    live = [r for r in reviewed if not r["withdrawn"]]
    live_un = [u for u in unreviewed if not u["withdrawn"]]
    holders = {}
    for kind, recs in (("reviewed", live), ("unreviewed", live_un)):
        for r in recs:
            for c in r["cves"]:
                holders.setdefault(c, []).append({"id": r["id"], "kind": kind, "packages": r["packages"]})
    linking = {}
    for u in live_un:
        for g in u["linked"]:
            linking.setdefault(g, []).append(u)
    alias_states = {}
    rows, replacements, mismatch, missing = [], [], [], []
    for r in live:
        recs = {c: lookup(c) for c in r["cves"]}
        for c, rec in recs.items():
            st = rec["state"] if rec else "MISSING"
            alias_states[st] = alias_states.get(st, 0) + 1
            if rec is None:
                missing.append({"reviewed": r["id"], "cve": c, "reviewed_published": r["published"]})
            elif (st == "PUBLISHED" and rec["ghsas"] and r["id"] not in rec["ghsas"]):
                mismatch.append({"reviewed": r["id"], "cve": c, "cve_cites": rec["ghsas"],
                                 "assigner": rec["assigner"], "reviewed_summary": r.get("summary", ""),
                                 "cve_text": rec["text"]})
        rejected = [c for c in r["cves"] if recs[c] and recs[c]["state"] == "REJECTED"]
        if not rejected:
            continue
        live_aliases = [c for c in r["cves"] if recs[c] and recs[c]["state"] == "PUBLISHED"]
        named = set()
        for c in rejected:
            named.update(x for x in CVE_FIND.findall(recs[c]["reason"]) if x != c)
        candidates = set(named)
        for u in linking.get(r["id"], []):
            candidates.update(u["cves"])
        candidates -= set(r["cves"])
        repl = []
        for c in sorted(candidates):
            rec = lookup(c)
            if not rec or rec["state"] != "PUBLISHED":
                continue
            via = "reason" if c in named else ("cites" if r["id"] in rec["ghsas"] else "")
            if not via:
                continue
            hold = holders.get(c, [])
            repl.append({
                "reviewed": r["id"], "replacement": c, "via": via, "assigner": rec["assigner"],
                "published": rec["published"][:10], "cites_reviewed": r["id"] in rec["ghsas"],
                "holders": ";".join(h["id"] for h in hold),
                "held_by_reviewed": any(h["kind"] == "reviewed" for h in hold),
                "only_packageless_unreviewed": bool(hold) and all(
                    h["kind"] == "unreviewed" and not h["packages"] for h in hold),
                "held_by_none": not hold,
                "reviewed_summary": r.get("summary", ""), "reviewed_details": r.get("details", ""),
                "replacement_text": rec["text"],
            })
        replacements.extend(repl)
        first = recs[rejected[0]]
        rows.append({
            "reviewed": r["id"], "reviewed_published": r["published"], "reviewed_modified": r["modified"],
            "packages": ";".join(r["packages"]), "aliases": ";".join(r["cves"]),
            "rejected": ";".join(rejected), "live_aliases": ";".join(live_aliases),
            "only_alias": not live_aliases,
            "rejected_assigner": ";".join(recs[c]["assigner"] for c in rejected),
            "rejected_date": ";".join(recs[c]["rejected"][:10] for c in rejected),
            "untouched_since_rejection": all(
                recs[c]["rejected"] and r["modified"] and r["modified"] < recs[c]["rejected"] for c in rejected),
            "reason_class": reason_class(first["reason"], rejected[0]),
            "reason": first["reason"],
            "has_replacement": bool(repl),
            "replacements": ";".join(x["replacement"] for x in repl),
            "summary": r.get("summary", ""),
        })
    stats = {"live_reviewed": len(live), "live_unreviewed_loaded": len(live_un),
             "reviewed_with_cve": sum(1 for r in live if r["cves"]),
             "alias_states": dict(sorted(alias_states.items()))}
    return {"rows": rows, "replacements": replacements, "mismatch": mismatch,
            "missing": missing, "stats": stats}


# ---------- verdicts ----------

def rate(k, n, threshold):
    if n == 0:
        return {"value": [k, n, None], "held": "n/a"}
    pct = round(100.0 * k / n, 1)
    return {"value": [k, n, pct], "held": "yes" if 100.0 * k / n >= threshold else "no"}


CLAIMS = {
    "P1": ">= 20 live reviewed GHSAs hold at least one CVE alias whose CVE record is REJECTED",
    "P2": ">= 50% of those GHSAs hold no PUBLISHED CVE alias at all",
    "P3": ">= 40% of those GHSAs have a found replacement: a PUBLISHED CVE named in the rejection reason "
          "or held by a linking 2025-26 unreviewed GHSA and citing the reviewed GHSA",
    "P4": ">= 60% of the distinct REJECTED aliases were assigned by GitHub_M or VulnCheck",
    "P5": ">= 70% of distinct replacement CVEs are held only by unreviewed GHSAs that list no package",
    "P6": ">= 80% of the seeded grading sample: the replacement CVE describes the same flaw as the "
          "reviewed GHSA (graded by hand from grading_sample.csv before results are opened)",
}


def verdicts(res):
    rows, repl = res["rows"], res["replacements"]
    out = {"P1": dict(value=len(rows), held="yes" if len(rows) >= 20 else "no")}
    if len(rows) < MIN_ROWS:
        for k in ("P2", "P3", "P4", "P5"):
            out[k] = {"value": len(rows), "held": "INCONCLUSIVE_UNDERPOWERED (fewer than %d rows)" % MIN_ROWS}
    else:
        out["P2"] = rate(sum(1 for r in rows if r["only_alias"]), len(rows), 50.0)
        out["P3"] = rate(sum(1 for r in rows if r["has_replacement"]), len(rows), 40.0)
        assigners = {}
        for r in rows:
            for c, a in zip(r["rejected"].split(";"), r["rejected_assigner"].split(";")):
                assigners[c] = a
        out["P4"] = rate(sum(1 for a in assigners.values() if a.lower() in ("github_m", "vulncheck")),
                         len(assigners), 60.0)
        distinct = {}
        for x in repl:
            distinct.setdefault(x["replacement"], x)
        out["P5"] = rate(sum(1 for x in distinct.values() if x["only_packageless_unreviewed"]),
                         len(distinct), 70.0)
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


def descriptive(res):
    rows, repl = res["rows"], res["replacements"]
    return dict(res["stats"], **{
        "rows": len(rows),
        "reason_classes": count_by(rows, lambda r: r["reason_class"]),
        "rejected_assigners": count_by(rows, lambda r: r["rejected_assigner"]),
        "untouched_since_rejection": sum(1 for r in rows if r["untouched_since_rejection"]),
        "rows_by_reviewed_year": dict(sorted(count_by(rows, lambda r: r["reviewed_published"][:4]).items())),
        "replacement_pairs": len(repl),
        "replacement_via": count_by(repl, lambda x: x["via"]),
        "replacement_held_by_reviewed": sum(1 for x in repl if x["held_by_reviewed"]),
        "replacement_held_by_none": sum(1 for x in repl if x["held_by_none"]),
        "mismatch_aliases": len(res["mismatch"]),
        "missing_aliases": len(res["missing"]),
    })


def grading_sample(replacements, n=SAMPLE_N, seed=SEED):
    """Seeded sample of reviewed GHSAs (one replacement each) for hand grading."""
    by = {}
    for x in replacements:
        by.setdefault(x["reviewed"], x)
    ids = random.Random(seed).sample(sorted(by), min(n, len(by)))
    return [by[i] for i in ids]


# ---------- data ----------

def sync_db(data_dir):
    root = os.path.join(data_dir, "advisory-database")
    if not os.path.isdir(os.path.join(root, ".git")):
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
                        DB_URL, root], check=True)
    else:
        subprocess.run(["git", "-C", root, "fetch", "--depth", "1", "origin", "main"], check=True)
        subprocess.run(["git", "-C", root, "reset", "--hard", "FETCH_HEAD"], check=True)
    subprocess.run(["git", "-C", root, "sparse-checkout", "set"] + SPARSE, check=True)
    sha = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    date = subprocess.run(["git", "-C", root, "log", "-1", "--format=%cI"], check=True,
                          capture_output=True, text=True).stdout.strip()
    return root, sha, date


def load_dir(path, keep_text):
    recs = []
    for dirpath, _, files in os.walk(path):
        for f in files:
            if f.endswith(".json"):
                with open(os.path.join(dirpath, f), encoding="utf-8") as fh:
                    recs.append(parse_record(json.load(fh), keep_text))
    return recs


def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def pick_asset(release):
    for a in release.get("assets") or []:
        if (a.get("name") or "").endswith(ASSET_SUFFIX):
            return a["name"], a["browser_download_url"]
    raise ValueError("no %s asset in release %s" % (ASSET_SUFFIX, release.get("tag_name")))


def download_cve_list(tmpdir):
    release = json.loads(http_get(RELEASES_API).decode("utf-8"))
    name, url = pick_asset(release)
    path = os.path.join(tmpdir, name)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=300) as r, open(path, "wb") as fh:
        shutil.copyfileobj(r, fh, 1 << 20)
    return path, release.get("tag_name") or "", name


# ---------- outputs ----------

ROW_COLS = ["reviewed", "reviewed_published", "reviewed_modified", "packages", "aliases", "rejected",
            "live_aliases", "only_alias", "rejected_assigner", "rejected_date", "untouched_since_rejection",
            "reason_class", "reason", "has_replacement", "replacements", "summary"]
REPL_COLS = ["reviewed", "replacement", "via", "assigner", "published", "cites_reviewed", "holders",
             "held_by_reviewed", "only_packageless_unreviewed", "held_by_none", "reviewed_summary",
             "replacement_text"]
MISMATCH_COLS = ["reviewed", "cve", "cve_cites", "assigner", "reviewed_summary", "cve_text"]
MISSING_COLS = ["reviewed", "cve", "reviewed_published"]
# The grading sample carries no CVE-record states, holders or counts: only the two texts.
SAMPLE_COLS = ["reviewed", "replacement", "reviewed_summary", "reviewed_details", "replacement_text"]


def cell(v):
    return ";".join(v) if isinstance(v, list) else v


def write_csv(path, cols, items, extra=None):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols + ([extra] if extra else []))
        for r in items:
            w.writerow([cell(r[c]) for c in cols] + ([""] if extra else []))


def write_outputs(out_dir, result, res, sample):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1)
    write_csv(os.path.join(out_dir, "rows.csv"), ROW_COLS, res["rows"])
    write_csv(os.path.join(out_dir, "replacements.csv"), REPL_COLS, res["replacements"])
    write_csv(os.path.join(out_dir, "mismatch.csv"), MISMATCH_COLS, res["mismatch"])
    write_csv(os.path.join(out_dir, "missing.csv"), MISSING_COLS, res["missing"])
    write_csv(os.path.join(out_dir, "grading_sample.csv"), SAMPLE_COLS, sample, extra="grade")
    lines = ["# Rejected-alias census S6: job output", "",
             "advisory-database commit %s (%s); CVE List release %s (%s), read %s." % (
                 result["db_commit"], result["db_commit_date"], result["cve_release"],
                 result["cve_asset"], result["cve_read_at"]), "",
             "| Prediction | Claim | Value [k, n, %] | Held |", "|---|---|---|---|"]
    for k, v in result["verdicts"].items():
        lines.append("| %s | %s | %s | %s |" % (k, v["claim"], json.dumps(v["value"]), v["held"]))
    lines += ["", "Descriptive: %s" % json.dumps(result["descriptive"])]
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    root, sha, date = sync_db(args.data_dir)
    reviewed = load_dir(os.path.join(root, "advisories", "github-reviewed"), keep_text=True)
    unreviewed = []
    for year in ("2025", "2026"):
        unreviewed += load_dir(os.path.join(root, "advisories", "unreviewed", year), keep_text=False)
    tmpdir = tempfile.mkdtemp(prefix="cvelist-")
    try:
        path, tag, asset = download_cve_list(tmpdir)
        cves = CveList(path, tmpdir)
        if cves.uses_inner():
            os.remove(path)
        read_at = now()
        res = analyse(reviewed, unreviewed, cves.get)
        cves.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    del reviewed, unreviewed
    sample = grading_sample(res["replacements"])
    result = {
        "db_commit": sha, "db_commit_date": date, "seed": SEED,
        "cve_release": tag, "cve_asset": asset, "cve_read_at": read_at,
        "verdicts": verdicts(res), "descriptive": descriptive(res),
        "sample": [[s["reviewed"], s["replacement"]] for s in sample],
    }
    write_outputs(args.out_dir, result, res, sample)
    # Print no counts or verdicts: P6 is graded from grading_sample.csv before anyone reads them.
    print("done: outputs written to %s" % args.out_dir)


if __name__ == "__main__":
    main()
