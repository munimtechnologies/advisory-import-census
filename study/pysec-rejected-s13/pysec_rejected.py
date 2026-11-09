"""PyPA rejected-CVE census (pre-registered study S13, see PREREG.md).

Question: how many live (not withdrawn) PYSEC advisories in the Python Packaging Authority's
advisory database (pypa/advisory-database, the data behind pip-audit and PyPI's JSON API) still
rest on a CVE that its CNA has REJECTED, and does GitHub's Advisory Database already treat the same
flaw as withdrawn?

Data (all public, pinned and recorded in results.json):
  - pypa/advisory-database, shallow git clone of main; commit SHA and date recorded.
  - github/advisory-database, sparse blob-filtered shallow clone of advisories/github-reviewed;
    commit SHA and date recorded.
  - The CVE Program's bulk CVE List release (CVEProject/cvelistV5, latest release asset
    *_all_CVEs_at_midnight.zip.zip), read in a temporary folder and deleted afterwards. Release tag
    recorded. CVE IDs not in the list (RESERVED or never assigned) count as MISSING.

Outputs (--out-dir): results.json, RESULTS-job.md, rows.csv, pr_candidates.csv, missing.csv,
grading_sample.csv. Stdlib plus PyYAML. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.

0.1.1 (2026-11-09, correction found while grading P6 by hand): replacement CVEs are now read from
the FULL rejection reason and from the CVE record's `replacedBy` field. 0.1.0 searched only the
first 300 characters of the reason (the display copy), so a reason that names its replacement late
(CVE-2025-34351 -> CVE-2023-48022) was classed WITHDRAW_CANDIDATE instead of REPLACE_ALIAS.
The pre-registered definitions, thresholds and seed are unchanged.
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

VERSION = "0.1.1"
PYPA_URL = "https://github.com/pypa/advisory-database.git"
GHDB_URL = "https://github.com/github/advisory-database.git"
GHDB_SPARSE = ["advisories/github-reviewed"]
RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
ASSET_SUFFIX = "_all_CVEs_at_midnight.zip.zip"
UA = "advisory-import-census-pysec-rejected/0.1.1 (MV2, Munim, Inc.; mv2@munimtech.com)"
SEED = 20261108
SAMPLE_N = 8
MIN_ROWS = 5
# Sanity gate: generous lower bounds on what each pinned input must contain, so a broken clone or a
# truncated download cannot be graded. They are floors, not expected values.
GATE = {"pysec_files": 2000, "pysec_parse_error_rate": 0.01, "cve_records": 200000,
        "reviewed_ghsas": 15000}
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
CVE_FIND = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
GHSA_RE = re.compile(r"^GHSA(-[0-9a-z]{4}){3}$", re.IGNORECASE)
CVE_FILE = re.compile(r"(?:^|/)(CVE-[0-9]{4}-[0-9]{4,})\.json$")


def ts(v):
    """Normalise a timestamp (string or datetime from YAML) to 'YYYY-MM-DDTHH:MM:SS' or ''."""
    if v is None or v == "":
        return ""
    if isinstance(v, datetime.datetime):
        if v.tzinfo is not None:
            v = v.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return v.strftime("%Y-%m-%dT%H:%M:%S")
    if isinstance(v, datetime.date):
        return v.strftime("%Y-%m-%dT00:00:00")
    s = str(v).strip().replace(" ", "T")
    return s[:19]


def squash(text, n):
    return " ".join(str(text or "").split())[:n]


def norm_ghsa(s):
    return "GHSA-" + s[5:].lower()


# ---------- PYSEC records ----------

def parse_pysec(obj, path):
    """Reduce one PYSEC record (already parsed from YAML) to the fields this study needs."""
    aliases = [str(a) for a in obj.get("aliases") or []]
    pkgs = set()
    for a in obj.get("affected") or []:
        p = (a or {}).get("package") or {}
        if p.get("name"):
            pkgs.add(str(p["name"]))
    return {
        "id": str(obj.get("id") or ""),
        "path": path.replace("\\", "/"),
        "withdrawn": ts(obj.get("withdrawn")),
        "published": ts(obj.get("published")),
        "modified": ts(obj.get("modified")),
        "cves": sorted(set(a for a in aliases if CVE_RE.match(a))),
        "ghsas": sorted(set(norm_ghsa(a) for a in aliases if GHSA_RE.match(a))),
        "packages": sorted(pkgs),
        "summary": squash(obj.get("summary") or obj.get("details"), 200),
    }


def load_pysec(root, yaml_mod):
    """Parse every vulns/**/PYSEC-*.yaml under root. Returns (records, n_files, errors)."""
    recs, n, errors = [], 0, []
    base = os.path.join(root, "vulns")
    for dirpath, _, files in os.walk(base):
        for f in sorted(files):
            if not (f.startswith("PYSEC-") and f.endswith(".yaml")):
                continue
            n += 1
            full = os.path.join(dirpath, f)
            rel = os.path.relpath(full, root)
            try:
                with open(full, encoding="utf-8") as fh:
                    obj = yaml_mod.safe_load(fh)
                if not isinstance(obj, dict) or not obj.get("id"):
                    raise ValueError("no id")
                recs.append(parse_pysec(obj, rel))
            except Exception as e:  # a broken file is counted, not fatal
                errors.append({"path": rel.replace("\\", "/"), "error": squash(e, 120)})
    return recs, n, errors


# ---------- GitHub reviewed advisories ----------

def load_reviewed(root):
    """{ghsa_id: {"withdrawn": bool, "cves": [...]}} for advisories/github-reviewed."""
    out = {}
    base = os.path.join(root, "advisories", "github-reviewed")
    for dirpath, _, files in os.walk(base):
        for f in files:
            if f.endswith(".json"):
                with open(os.path.join(dirpath, f), encoding="utf-8") as fh:
                    obj = json.load(fh)
                out[norm_ghsa(obj["id"])] = {
                    "withdrawn": bool(obj.get("withdrawn")),
                    "cves": sorted(x for x in obj.get("aliases") or [] if CVE_RE.match(x)),
                }
    return out


# ---------- CVE records ----------

def parse_cve(obj):
    meta = obj.get("cveMetadata") or {}
    cna = (obj.get("containers") or {}).get("cna") or {}
    rej = " ".join(d.get("value") or "" for d in cna.get("rejectedReasons") or [])
    cid = meta.get("cveId") or ""
    replaced = [str(x) for x in cna.get("replacedBy") or [] if CVE_RE.match(str(x))]
    # 0.1.1: CVE IDs named anywhere in the full reason, plus replacedBy (not the 300-char copy).
    named = sorted((set(CVE_FIND.findall(rej)) | set(replaced)) - {cid})
    return {
        "id": cid,
        "state": meta.get("state") or "",
        "assigner": meta.get("assignerShortName") or "",
        "published": ts(meta.get("datePublished")),
        "rejected": ts(meta.get("dateRejected")),
        "reason": squash(rej, 300),
        "named": named,
        "replaced_by": sorted(set(replaced)),
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
            or "disput" in low or "not considered a vulnerab" in low or "not valid" in low):
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

    def __len__(self):
        return len(self.index)

    def get(self, cve):
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

def ghsa_state(ghsas, reviewed):
    """none | withdrawn (any alias withdrawn in GitHub's DB) | live | not_in_reviewed."""
    if not ghsas:
        return "none"
    states = []
    for g in ghsas:
        r = reviewed.get(g)
        states.append("not_in_reviewed" if r is None else ("withdrawn" if r["withdrawn"] else "live"))
    for s in ("withdrawn", "live"):
        if s in states:
            return s
    return "not_in_reviewed"


def named_cves(rec):
    """CVE IDs a rejected record points to. Uses the full-reason list when present (0.1.1)."""
    if "named" in rec:
        return set(rec["named"])
    return set(x for x in CVE_FIND.findall(rec.get("reason") or "") if x != rec.get("id"))


def analyse(pysec, reviewed, lookup):
    """Rows for live PYSEC records holding a REJECTED CVE alias. lookup(cve) -> record or None."""
    live = [p for p in pysec if not p["withdrawn"]]
    alias_states, rows, missing = {}, [], []
    for p in live:
        recs = {c: lookup(c) for c in p["cves"]}
        for c, rec in recs.items():
            st = rec["state"] if rec else "MISSING"
            alias_states[st] = alias_states.get(st, 0) + 1
            if rec is None:
                missing.append({"pysec": p["id"], "path": p["path"], "cve": c, "pysec_published": p["published"]})
        rejected = [c for c in p["cves"] if recs[c] and recs[c]["state"] == "REJECTED"]
        if not rejected:
            continue
        published = [c for c in p["cves"] if recs[c] and recs[c]["state"] == "PUBLISHED"]
        named = set()
        for c in rejected:
            named.update(x for x in named_cves(recs[c]) if x != c)
        repl = sorted(c for c in named - set(p["cves"])
                      if lookup(c) is not None and lookup(c)["state"] == "PUBLISHED")
        if published:
            action = "DROP_ALIAS"
        elif repl:
            action = "REPLACE_ALIAS"
        else:
            action = "WITHDRAW_CANDIDATE"
        rej_dates = [recs[c]["rejected"] for c in rejected]
        first = recs[rejected[0]]
        rows.append({
            "pysec": p["id"], "path": p["path"], "packages": ";".join(p["packages"]),
            "pysec_published": p["published"], "pysec_modified": p["modified"],
            "cves": ";".join(p["cves"]), "rejected": ";".join(rejected),
            "published_cves": ";".join(published), "replacement": ";".join(repl),
            "action": action,
            "rejected_assigner": ";".join(recs[c]["assigner"] for c in rejected),
            "rejected_date": ";".join(d[:10] for d in rej_dates),
            "untouched_since_rejection": all(d and p["modified"] and p["modified"] < d for d in rej_dates),
            "rejected_after_publish": all(d and p["published"] and d > p["published"] for d in rej_dates),
            "reason_class": reason_class(first["reason"], rejected[0]),
            "reason": first["reason"],
            "ghsas": ";".join(p["ghsas"]),
            "ghsa_state": ghsa_state(p["ghsas"], reviewed),
            "summary": p["summary"],
        })
    rows.sort(key=lambda r: r["pysec"])
    stats = {"pysec_records": len(pysec), "pysec_withdrawn": len(pysec) - len(live),
             "pysec_live": len(live), "live_with_cve": sum(1 for p in live if p["cves"]),
             "alias_states": dict(sorted(alias_states.items()))}
    return {"rows": rows, "missing": missing, "stats": stats}


# ---------- verdicts ----------

CLAIMS = {
    "P1": ">= 10 live PYSEC records hold at least one CVE alias whose CVE record is REJECTED",
    "P2": ">= 50% of those records are WITHDRAW_CANDIDATE (no PUBLISHED CVE alias and no PUBLISHED "
          "replacement CVE named in the rejection reason)",
    "P3": ">= 40% of those records that list a GHSA alias have a GHSA alias that GitHub's Advisory "
          "Database has withdrawn",
    "P4": ">= 70% of those records were not modified after their CVE was rejected",
    "P5": ">= 80% of those records: every rejected CVE was rejected after the PYSEC record was published",
    "P6": ">= 75% of the seeded sample of WITHDRAW_CANDIDATE records are still PR-ready when checked live "
          "(graded by hand after the run)",
}


def rate(k, n, threshold):
    if n == 0:
        return {"value": [k, n, None], "held": "n/a"}
    pct = round(100.0 * k / n, 1)
    return {"value": [k, n, pct], "held": "yes" if 100.0 * k / n >= threshold else "no"}


def verdicts(res):
    rows = res["rows"]
    out = {"P1": {"value": len(rows), "held": "yes" if len(rows) >= 10 else "no"}}
    if len(rows) < MIN_ROWS:
        for k in ("P2", "P3", "P4", "P5"):
            out[k] = {"value": len(rows), "held": "INCONCLUSIVE_UNDERPOWERED (fewer than %d rows)" % MIN_ROWS}
    else:
        out["P2"] = rate(sum(1 for r in rows if r["action"] == "WITHDRAW_CANDIDATE"), len(rows), 50.0)
        with_g = [r for r in rows if r["ghsa_state"] != "none"]
        out["P3"] = rate(sum(1 for r in with_g if r["ghsa_state"] == "withdrawn"), len(with_g), 40.0)
        out["P4"] = rate(sum(1 for r in rows if r["untouched_since_rejection"]), len(rows), 70.0)
        out["P5"] = rate(sum(1 for r in rows if r["rejected_after_publish"]), len(rows), 80.0)
    out["P6"] = {"value": None, "held": "graded by hand after the run"}
    for k in out:
        out[k]["claim"] = CLAIMS[k]
    return dict(sorted(out.items()))


def gate(counts):
    """List of failed gate checks (empty means the inputs are sane enough to grade)."""
    fails = []
    if counts["pysec_files"] < GATE["pysec_files"]:
        fails.append("pysec_files %d < %d" % (counts["pysec_files"], GATE["pysec_files"]))
    if counts["pysec_files"] and counts["pysec_parse_errors"] / counts["pysec_files"] > GATE["pysec_parse_error_rate"]:
        fails.append("pysec parse errors %d of %d" % (counts["pysec_parse_errors"], counts["pysec_files"]))
    if counts["cve_records"] < GATE["cve_records"]:
        fails.append("cve_records %d < %d" % (counts["cve_records"], GATE["cve_records"]))
    if counts["reviewed_ghsas"] < GATE["reviewed_ghsas"]:
        fails.append("reviewed_ghsas %d < %d" % (counts["reviewed_ghsas"], GATE["reviewed_ghsas"]))
    return fails


def count_by(items, fn):
    out = {}
    for x in items:
        k = fn(x)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def descriptive(res):
    rows = res["rows"]
    return dict(res["stats"], **{
        "rows": len(rows),
        "actions": count_by(rows, lambda r: r["action"]),
        "reason_classes": count_by(rows, lambda r: r["reason_class"]),
        "rejected_assigners": count_by(rows, lambda r: r["rejected_assigner"]),
        "ghsa_states": count_by(rows, lambda r: r["ghsa_state"]),
        "rows_by_pysec_year": dict(sorted(count_by(rows, lambda r: r["pysec"][6:10]).items())),
        "missing_aliases": len(res["missing"]),
    })


def grading_sample(rows, n=SAMPLE_N, seed=SEED):
    cands = sorted(r["pysec"] for r in rows if r["action"] == "WITHDRAW_CANDIDATE")
    pick = set(random.Random(seed).sample(cands, min(n, len(cands))))
    return [r for r in rows if r["pysec"] in pick]


# ---------- data ----------

def git(*args, capture=False):
    r = subprocess.run(["git"] + list(args), check=True, capture_output=capture, text=True)
    return r.stdout.strip() if capture else ""


def sync_repo(url, root, sparse=None):
    if not os.path.isdir(os.path.join(root, ".git")):
        cmd = ["clone", "--depth", "1"]
        if sparse:
            cmd += ["--filter=blob:none", "--sparse"]
        git(*(cmd + [url, root]))
    else:
        git("-C", root, "fetch", "--depth", "1", "origin", "main")
        git("-C", root, "reset", "--hard", "FETCH_HEAD")
    if sparse:
        git(*(["-C", root, "sparse-checkout", "set"] + sparse))
    return git("-C", root, "rev-parse", "HEAD", capture=True), git("-C", root, "log", "-1", "--format=%cI", capture=True)


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
    with urllib.request.urlopen(req, timeout=600) as r, open(path, "wb") as fh:
        shutil.copyfileobj(r, fh, 1 << 20)
    return path, release.get("tag_name") or "", name


# ---------- outputs ----------

ROW_COLS = ["pysec", "path", "packages", "pysec_published", "pysec_modified", "cves", "rejected",
            "published_cves", "replacement", "action", "rejected_assigner", "rejected_date",
            "untouched_since_rejection", "rejected_after_publish", "reason_class", "reason", "ghsas",
            "ghsa_state", "summary"]
PR_COLS = ["pysec", "path", "rejected", "rejected_date", "rejected_assigner", "reason_class", "ghsas",
           "ghsa_state", "reason"]
MISSING_COLS = ["pysec", "path", "cve", "pysec_published"]


def write_csv(path, cols, items, extra=None):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(cols + ([extra] if extra else []))
        for r in items:
            w.writerow([r[c] for c in cols] + ([""] if extra else []))


def write_outputs(out_dir, result, res, sample):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=1)
    write_csv(os.path.join(out_dir, "rows.csv"), ROW_COLS, res["rows"])
    write_csv(os.path.join(out_dir, "pr_candidates.csv"), PR_COLS,
              [r for r in res["rows"] if r["action"] == "WITHDRAW_CANDIDATE"])
    write_csv(os.path.join(out_dir, "missing.csv"), MISSING_COLS, res["missing"])
    write_csv(os.path.join(out_dir, "grading_sample.csv"), PR_COLS, sample, extra="grade")
    lines = ["# PyPA rejected-CVE census S13: job output", "",
             "pypa/advisory-database commit %s (%s); github/advisory-database commit %s (%s); "
             "CVE List release %s (%s), read %s. Script %s." % (
                 result["pypa_commit"], result["pypa_commit_date"], result["ghdb_commit"],
                 result["ghdb_commit_date"], result["cve_release"], result["cve_asset"],
                 result["cve_read_at"], VERSION), "",
             "Gate: %s; counts %s" % ("PASSED" if not result["gate_failures"] else
                                      "FAILED: " + "; ".join(result["gate_failures"]),
                                      json.dumps(result["counts"])), ""]
    if result["verdicts"]:
        lines += ["| Prediction | Claim | Value [k, n, %] | Held |", "|---|---|---|---|"]
        for k, v in result["verdicts"].items():
            lines.append("| %s | %s | %s | %s |" % (k, v["claim"], json.dumps(v["value"]), v["held"]))
        lines += ["", "Descriptive: %s" % json.dumps(result["descriptive"])]
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    import yaml  # installed in the job's setup step (PyYAML)
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--version", action="version", version="pysec_rejected.py " + VERSION)
    args = ap.parse_args()

    pypa_root = os.path.join(args.data_dir, "pypa-advisory-database")
    pypa_sha, pypa_date = sync_repo(PYPA_URL, pypa_root)
    gh_root = os.path.join(args.data_dir, "advisory-database")
    gh_sha, gh_date = sync_repo(GHDB_URL, gh_root, sparse=GHDB_SPARSE)
    pysec, n_files, errors = load_pysec(pypa_root, yaml)
    reviewed = load_reviewed(gh_root)
    tmpdir = tempfile.mkdtemp(prefix="cvelist-")
    try:
        path, tag, asset = download_cve_list(tmpdir)
        cves = CveList(path, tmpdir)
        if cves.uses_inner():
            os.remove(path)
        read_at = now()
        counts = {"pysec_files": n_files, "pysec_parse_errors": len(errors), "cve_records": len(cves),
                  "reviewed_ghsas": len(reviewed)}
        fails = gate(counts)
        res = analyse(pysec, reviewed, cves.get) if not fails else {"rows": [], "missing": [], "stats": {}}
        cves.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    sample = grading_sample(res["rows"]) if not fails else []
    result = {
        "script_version": VERSION, "seed": SEED,
        "pypa_commit": pypa_sha, "pypa_commit_date": pypa_date,
        "ghdb_commit": gh_sha, "ghdb_commit_date": gh_date,
        "cve_release": tag, "cve_asset": asset, "cve_read_at": read_at,
        "counts": counts, "gate_failures": fails, "parse_errors": errors[:50],
        "verdicts": verdicts(res) if not fails else {},
        "descriptive": descriptive(res) if not fails else {},
        "sample": [s["pysec"] for s in sample],
    }
    write_outputs(args.out_dir, result, res, sample)
    print("gate: %s" % ("PASSED" if not fails else "FAILED " + "; ".join(fails)))
    print("done: outputs written to %s" % args.out_dir)


if __name__ == "__main__":
    main()
