"""Cross-database rejected-CVE census (pre-registered study S15, see PREREG.md).

Question: S13 found 21 live PYSEC advisories that rest on a CVE its CNA has REJECTED. Do the other
source databases that OSV.dev serves to scanners (the Go vulnerability database GO-*, RustSec
RUSTSEC-*, Haskell HSEC-*, R RSEC-*, Julia JLSEC-*, the Erlang Ecosystem Foundation EEF-*, and others)
carry the same problem, and how does each compare with PyPA measured in the same run?

Data (all public, pinned and recorded in results.json):
  - OSV.dev's per-ecosystem exports https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip
    for the ecosystems in ECOSYSTEMS; sha256, size and Last-Modified header of each zip recorded.
  - The CVE Program's bulk CVE List release (CVEProject/cvelistV5, latest release asset
    *_all_CVEs_at_midnight.zip.zip), read in a temporary folder and deleted afterwards. Release tag
    recorded. CVE IDs not in the list (RESERVED or never assigned) count as MISSING.

A "source record" is an OSV record whose ID prefix is not GHSA, MAL, CVE or OSV (those are GitHub's,
malicious-package, NVD-converted and OSS-Fuzz records). GitHub (GHSA) records in the same exports
are used only to look up whether a source record's GHSA alias is withdrawn.

Outputs (--out-dir): results.json, RESULTS-job.md, rows.csv, missing.csv, grading_sample.csv.
Stdlib only. Apache-2.0. Made with AI agents working for MV2 of Munim, Inc.
"""
import argparse
import csv
import datetime
import hashlib
import json
import os
import random
import re
import shutil
import tempfile
import urllib.parse
import urllib.request
import zipfile

VERSION = "0.1.0"
OSV_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/%s/all.zip"
ECOSYSTEMS = ["Go", "crates.io", "Hackage", "GHC", "CRAN", "Julia", "Hex", "opam", "Pub",
              "SwiftURL", "PyPI"]
NOT_SOURCE = {"GHSA", "MAL", "CVE", "OSV"}
RELEASES_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
ASSET_SUFFIX = "_all_CVEs_at_midnight.zip.zip"
UA = "advisory-import-census-osv-rejected/0.1.0 (MV2, Munim, Inc.; mv2@munimtech.com)"
SEED = 20261109
SAMPLE_N = 6
MIN_ROWS = 5
MIN_GO_ROWS = 3
# Sanity floors on the pinned inputs, so a truncated download cannot be graded. Floors, not expectations.
GATE = {"go_records": 1000, "rustsec_records": 500, "pysec_records": 2000, "ghsa_records": 2000,
        "cve_records": 200000, "parse_error_rate": 0.01}
CVE_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
CVE_FIND = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
GHSA_RE = re.compile(r"GHSA(-[0-9a-zA-Z]{4}){3}")
CVE_FILE = re.compile(r"(?:^|/)(CVE-[0-9]{4}-[0-9]{4,})\.json$")


def ts(v):
    """Normalise an RFC3339 timestamp string to 'YYYY-MM-DDTHH:MM:SS' or ''."""
    if not v:
        return ""
    return str(v).strip().replace(" ", "T")[:19]


def squash(text, n):
    return " ".join(str(text or "").split())[:n]


def prefix(vid):
    return str(vid or "").split("-", 1)[0].upper()


def is_cve(s):
    return bool(CVE_RE.fullmatch(str(s)))


def is_ghsa(s):
    return bool(GHSA_RE.fullmatch(str(s)))


def norm_ghsa(s):
    return "GHSA-" + str(s)[5:].lower()


# ---------- OSV records ----------

def parse_osv(obj, ecosystem):
    """Reduce one OSV record to the fields this study needs."""
    aliases = [str(a) for a in obj.get("aliases") or []]
    pkgs = set()
    for a in obj.get("affected") or []:
        p = (a or {}).get("package") or {}
        if p.get("name"):
            pkgs.add(str(p["name"]))
    ds = obj.get("database_specific") or {}
    review = ds.get("review_status") if isinstance(ds, dict) else None
    vid = str(obj.get("id") or "")
    return {
        "id": vid,
        "source": prefix(vid),
        "ecosystems": [ecosystem],
        "withdrawn": ts(obj.get("withdrawn")),
        "published": ts(obj.get("published")),
        "modified": ts(obj.get("modified")),
        "cves": sorted(set(a for a in aliases if is_cve(a))),
        "ghsas": sorted(set(norm_ghsa(a) for a in aliases if is_ghsa(a))),
        "packages": sorted(pkgs),
        "review_status": str(review or ""),
        "summary": squash(obj.get("summary") or obj.get("details"), 200),
    }


def merge_record(store, rec):
    """Add rec to store (by id); a record exported under several ecosystems is kept once."""
    old = store.get(rec["id"])
    if old is None:
        store[rec["id"]] = rec
    else:
        old["ecosystems"] = sorted(set(old["ecosystems"]) | set(rec["ecosystems"]))


def load_zip(path, ecosystem, sources, ghsas, errors):
    """Read every *.json record in one OSV ecosystem zip. Returns the number of records read."""
    n = 0
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            n += 1
            try:
                obj = json.loads(zf.read(name).decode("utf-8-sig"))
                if not isinstance(obj, dict) or not obj.get("id"):
                    raise ValueError("no id")
            except Exception as e:  # a broken record is counted, not fatal
                errors.append({"ecosystem": ecosystem, "file": name, "error": squash(e, 120)})
                continue
            p = prefix(obj["id"])
            if p == "GHSA":
                ghsas[norm_ghsa(obj["id"])] = bool(obj.get("withdrawn"))
            elif p not in NOT_SOURCE:
                merge_record(sources, parse_osv(obj, ecosystem))
    return n


# ---------- CVE records ----------

def parse_cve(obj):
    meta = obj.get("cveMetadata") or {}
    cna = (obj.get("containers") or {}).get("cna") or {}
    rej = " ".join(d.get("value") or "" for d in cna.get("rejectedReasons") or [])
    cid = meta.get("cveId") or ""
    replaced = [str(x) for x in cna.get("replacedBy") or [] if is_cve(x)]
    # Replacement CVEs are read from the FULL reason and from replacedBy (lesson of S13 0.1.0).
    named = sorted((set(CVE_FIND.findall(rej)) | set(replaced)) - {cid})
    return {
        "id": cid,
        "state": meta.get("state") or "",
        "assigner": meta.get("assignerShortName") or "",
        "published": ts(meta.get("datePublished")),
        "rejected": ts(meta.get("dateRejected")),
        "reason": squash(rej, 300),
        "named": named,
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

def ghsa_state(ids, ghsas):
    """none | withdrawn (any alias withdrawn in the export) | live | not_in_export."""
    if not ids:
        return "none"
    states = []
    for g in ids:
        w = ghsas.get(g)
        states.append("not_in_export" if w is None else ("withdrawn" if w else "live"))
    for s in ("withdrawn", "live"):
        if s in states:
            return s
    return "not_in_export"


def analyse(sources, ghsas, lookup):
    """Rows for live source records holding a REJECTED CVE alias. lookup(cve) -> record or None."""
    recs_all = sorted(sources.values(), key=lambda r: r["id"])
    live = [r for r in recs_all if not r["withdrawn"]]
    per_source = {}
    rows, missing = [], []
    for p in live:
        s = per_source.setdefault(p["source"], {"records": 0, "live": 0, "live_with_cve": 0, "rows": 0})
        s["live"] += 1
        if p["cves"]:
            s["live_with_cve"] += 1
        recs = {c: lookup(c) for c in p["cves"]}
        for c, rec in recs.items():
            if rec is None:
                missing.append({"id": p["id"], "source": p["source"], "cve": c, "published": p["published"]})
        rejected = [c for c in p["cves"] if recs[c] and recs[c]["state"] == "REJECTED"]
        if not rejected:
            continue
        s["rows"] += 1
        published = [c for c in p["cves"] if recs[c] and recs[c]["state"] == "PUBLISHED"]
        named = set()
        for c in rejected:
            named.update(x for x in recs[c]["named"] if x != c)
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
            "id": p["id"], "source": p["source"], "ecosystems": ";".join(p["ecosystems"]),
            "packages": ";".join(p["packages"][:5]), "published": p["published"],
            "modified_osv": p["modified"], "review_status": p["review_status"],
            "cves": ";".join(p["cves"]), "rejected": ";".join(rejected),
            "published_cves": ";".join(published), "replacement": ";".join(repl), "action": action,
            "rejected_assigner": ";".join(recs[c]["assigner"] for c in rejected),
            "rejected_date": ";".join(d[:10] for d in rej_dates),
            "rejected_after_publish": all(d and p["published"] and d > p["published"] for d in rej_dates),
            "reason_class": reason_class(first["reason"], rejected[0]), "reason": first["reason"],
            "ghsas": ";".join(p["ghsas"]), "ghsa_state": ghsa_state(p["ghsas"], ghsas),
            "summary": p["summary"],
        })
    for r in recs_all:
        per_source.setdefault(r["source"], {"records": 0, "live": 0, "live_with_cve": 0, "rows": 0})
        per_source[r["source"]]["records"] += 1
    rows.sort(key=lambda r: (r["source"], r["id"]))
    return {"rows": rows, "missing": missing, "per_source": dict(sorted(per_source.items()))}


# ---------- verdicts ----------

CLAIMS = {
    "P1": ">= 5 live source records outside PyPA (not GHSA, MAL, CVE, OSV or PYSEC) hold at least one "
          "CVE alias whose CVE record is REJECTED",
    "P2": ">= 50% of those non-PyPA rows are Go vulnerability database (GO-) records",
    "P3": ">= 60% of the GO- rows have review_status UNREVIEWED",
    "P4": ">= 50% of the non-PyPA rows that list a GHSA alias have that GHSA live (not withdrawn) in "
          "OSV's export",
    "P5": "The share of live GO- and RUSTSEC- records with a CVE alias that hold a REJECTED CVE is lower "
          "than the same share for PYSEC records in the same run",
    "P6": ">= 75% of the seeded sample of non-PyPA WITHDRAW_CANDIDATE rows are still live with a REJECTED "
          "CVE when checked at the source database (graded by hand after the run)",
}


def rate(k, n, threshold):
    if n == 0:
        return {"value": [k, n, None], "held": "n/a"}
    pct = round(100.0 * k / n, 1)
    return {"value": [k, n, pct], "held": "yes" if 100.0 * k / n >= threshold else "no"}


def share(per_source, keys):
    k = sum(per_source.get(x, {}).get("rows", 0) for x in keys)
    n = sum(per_source.get(x, {}).get("live_with_cve", 0) for x in keys)
    return k, n


def verdicts(res):
    rows = [r for r in res["rows"] if r["source"] != "PYSEC"]
    out = {"P1": {"value": len(rows), "held": "yes" if len(rows) >= 5 else "no"}}
    under = "INCONCLUSIVE_UNDERPOWERED (fewer than %d rows)"
    if len(rows) < MIN_ROWS:
        for k in ("P2", "P3", "P4"):
            out[k] = {"value": len(rows), "held": under % MIN_ROWS}
    else:
        go = [r for r in rows if r["source"] == "GO"]
        out["P2"] = rate(len(go), len(rows), 50.0)
        if len(go) < MIN_GO_ROWS:
            out["P3"] = {"value": len(go), "held": under % MIN_GO_ROWS}
        else:
            out["P3"] = rate(sum(1 for r in go if r["review_status"] == "UNREVIEWED"), len(go), 60.0)
        with_g = [r for r in rows if r["ghsa_state"] != "none"]
        out["P4"] = rate(sum(1 for r in with_g if r["ghsa_state"] == "live"), len(with_g), 50.0)
    k1, n1 = share(res["per_source"], ["GO", "RUSTSEC"])
    k2, n2 = share(res["per_source"], ["PYSEC"])
    if n1 == 0 or n2 == 0:
        out["P5"] = {"value": [k1, n1, k2, n2], "held": "n/a"}
    else:
        a, b = 100.0 * k1 / n1, 100.0 * k2 / n2
        out["P5"] = {"value": [k1, n1, round(a, 3), k2, n2, round(b, 3)], "held": "yes" if a < b else "no"}
    out["P6"] = {"value": None, "held": "graded by hand after the run"}
    for k in out:
        out[k]["claim"] = CLAIMS[k]
    return dict(sorted(out.items()))


def gate(counts):
    """List of failed gate checks (empty means the inputs are sane enough to grade)."""
    fails = []
    for key in ("go_records", "rustsec_records", "pysec_records", "ghsa_records", "cve_records"):
        if counts[key] < GATE[key]:
            fails.append("%s %d < %d" % (key, counts[key], GATE[key]))
    if counts["osv_files"] and counts["parse_errors"] / counts["osv_files"] > GATE["parse_error_rate"]:
        fails.append("parse errors %d of %d" % (counts["parse_errors"], counts["osv_files"]))
    return fails


def count_by(items, fn):
    out = {}
    for x in items:
        k = fn(x)
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def descriptive(res):
    rows = res["rows"]
    return {
        "per_source": res["per_source"],
        "rows": len(rows),
        "rows_by_source": count_by(rows, lambda r: r["source"]),
        "actions": count_by(rows, lambda r: r["action"]),
        "reason_classes": count_by(rows, lambda r: r["reason_class"]),
        "rejected_assigners": count_by(rows, lambda r: r["rejected_assigner"]),
        "ghsa_states": count_by(rows, lambda r: r["ghsa_state"]),
        "go_review_status": count_by([r for r in rows if r["source"] == "GO"],
                                     lambda r: r["review_status"] or "(absent = REVIEWED)"),
        "rejected_after_publish": count_by(rows, lambda r: r["rejected_after_publish"]),
        "missing_aliases": len(res["missing"]),
    }


def grading_sample(rows, n=SAMPLE_N, seed=SEED):
    cands = sorted(r["id"] for r in rows if r["source"] != "PYSEC" and r["action"] == "WITHDRAW_CANDIDATE")
    pick = set(random.Random(seed).sample(cands, min(n, len(cands))))
    return [r for r in rows if r["id"] in pick]


# ---------- data ----------

def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def download(url, path):
    """Download url to path; return {sha256, bytes, last_modified}."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    h = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(req, timeout=600) as r, open(path, "wb") as fh:
        lm = r.headers.get("Last-Modified") or ""
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            fh.write(chunk)
    return {"sha256": h.hexdigest(), "bytes": size, "last_modified": lm}


def pick_asset(release):
    for a in release.get("assets") or []:
        if (a.get("name") or "").endswith(ASSET_SUFFIX):
            return a["name"], a["browser_download_url"]
    raise ValueError("no %s asset in release %s" % (ASSET_SUFFIX, release.get("tag_name")))


# ---------- outputs ----------

ROW_COLS = ["id", "source", "ecosystems", "packages", "published", "modified_osv", "review_status", "cves",
            "rejected", "published_cves", "replacement", "action", "rejected_assigner", "rejected_date",
            "rejected_after_publish", "reason_class", "reason", "ghsas", "ghsa_state", "summary"]
SAMPLE_COLS = ["id", "source", "rejected", "rejected_date", "rejected_assigner", "review_status", "ghsas",
               "ghsa_state", "reason"]
MISSING_COLS = ["id", "source", "cve", "published"]


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
    write_csv(os.path.join(out_dir, "missing.csv"), MISSING_COLS, res["missing"])
    write_csv(os.path.join(out_dir, "grading_sample.csv"), SAMPLE_COLS, sample, extra="grade")
    lines = ["# Cross-database rejected-CVE census S15: job output", "",
             "CVE List release %s (%s), read %s. Script %s." % (
                 result["cve_release"], result["cve_asset"], result["cve_read_at"], VERSION), "",
             "OSV exports: " + "; ".join("%s %s (%d bytes, %s)" % (e, z["sha256"][:16], z["bytes"],
                                                                     z["last_modified"])
                                         for e, z in result["osv_zips"].items()), "",
             "Gate: %s; counts %s" % ("PASSED" if not result["gate_failures"] else
                                      "FAILED: " + "; ".join(result["gate_failures"]),
                                      json.dumps(result["counts"])), ""]
    if result["verdicts"]:
        lines += ["| Prediction | Claim | Value | Held |", "|---|---|---|---|"]
        for k, v in result["verdicts"].items():
            lines.append("| %s | %s | %s | %s |" % (k, v["claim"], json.dumps(v["value"]), v["held"]))
        lines += ["", "Descriptive: %s" % json.dumps(result["descriptive"])]
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-dir", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--version", action="version", version="osv_rejected.py " + VERSION)
    args = ap.parse_args()

    zdir = os.path.join(args.data_dir, "osv-s15")
    os.makedirs(zdir, exist_ok=True)
    sources, ghsas, errors, zips = {}, {}, [], {}
    n_files = 0
    for eco in ECOSYSTEMS:
        path = os.path.join(zdir, eco.replace(".", "_") + ".zip")
        zips[eco] = download(OSV_ZIP % urllib.parse.quote(eco), path)
        zips[eco]["records"] = load_zip(path, eco, sources, ghsas, errors)
        n_files += zips[eco]["records"]
    by_src = count_by(sources.values(), lambda r: r["source"])
    tmpdir = tempfile.mkdtemp(prefix="cvelist-")
    try:
        release = json.loads(http_get(RELEASES_API).decode("utf-8"))
        name, url = pick_asset(release)
        path = os.path.join(tmpdir, name)
        download(url, path)
        cves = CveList(path, tmpdir)
        if cves.uses_inner():
            os.remove(path)
        read_at = now()
        counts = {"osv_files": n_files, "parse_errors": len(errors), "source_records": len(sources),
                  "go_records": by_src.get("GO", 0), "rustsec_records": by_src.get("RUSTSEC", 0),
                  "pysec_records": by_src.get("PYSEC", 0), "ghsa_records": len(ghsas),
                  "cve_records": len(cves), "source_records_by_prefix": by_src}
        fails = gate(counts)
        res = analyse(sources, ghsas, cves.get) if not fails else {"rows": [], "missing": [], "per_source": {}}
        cves.close()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    sample = grading_sample(res["rows"]) if not fails else []
    result = {
        "script_version": VERSION, "seed": SEED, "osv_zips": zips,
        "cve_release": release.get("tag_name") or "", "cve_asset": name, "cve_read_at": read_at,
        "counts": counts, "gate_failures": fails, "parse_errors": errors[:50],
        "verdicts": verdicts(res) if not fails else {},
        "descriptive": descriptive(res) if not fails else {},
        "sample": [s["id"] for s in sample],
    }
    write_outputs(args.out_dir, result, res, sample)
    print("gate: %s" % ("PASSED" if not fails else "FAILED " + "; ".join(fails)))
    print("done: outputs written to %s" % args.out_dir)


if __name__ == "__main__":
    main()
