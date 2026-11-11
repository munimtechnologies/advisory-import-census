#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""actionable_s18b.py: which S18 rows could a vulnerability database actually add?

Study S18b of https://github.com/munimtechnologies/advisory-import-census (pre-registered in
study/repo-advisory-actionable-s18b/PREREG.md). S18 counted published Rust repository advisories that
are in none of GitHub's global Advisory Database, RustSec or OSV, matching by GHSA ID only. This script
takes S18's 332 graded rows and removes two kinds of false positive: advisories whose CVE is already
covered under another ID, and advisories whose Rust package names are not crates.io crates. It ranks
the rest by crates.io recent downloads.

Data read: S18's published rows.csv, OSV's crates.io export, the public REST list of each repository's
published advisories (unauthenticated), api.osv.dev, and the crates.io API (one request per second).
No usernames, credits or other personal data are stored.

Standard library only. Made with AI agents working in MV2's (Munim, Inc.) name.
"""
import argparse
import csv
import datetime as dt
import hashlib
import io
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile

__version__ = "0.1.0"

ROWS_URL = ("https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main/"
            "study/repo-advisory-census-s18/rows.csv")
ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip"
CRATES_API = "https://crates.io/api/v1/crates/"
CUTOFF = "2026-10-27"
SEED_REPO = "zip-rs/zip2"
EXPECT = (1720, 427, 332)          # S18 rows, NEITHER rows, graded NEITHER rows
SEED = 20261112
SAMPLE_N = 8
GATE_MIN_RUSTSEC = 500
NEG_CRATE = "mv2-s18b-no-such-crate-zz9"
UA = ("advisory-import-census-s18b/%s (+https://github.com/munimtechnologies/advisory-import-census; "
      "mv2@munimtech.com)" % __version__)

GHSA_PAT = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
CRATE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
NEXT_RE = re.compile(r'\s*<([^>]+)>\s*;\s*rel="next"\s*')
REPO_URL_RE = re.compile(r"https?://(?:www\.)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?(?:[/#?].*)?",
                         re.I)
UNRESOLVED = ("API_MISSING", "OSV_ERROR", "CRATE_ERROR")
ROW_FIELDS = ["repo", "ghsa_id", "published", "severity", "s18_cve", "cve_id", "status", "covered_by",
              "covered_same_crate", "rust_packages", "crates_found", "repo_match", "max_recent_downloads",
              "ranges"]
CRATE_FIELDS = ["name", "status", "canonical", "recent_downloads", "repository"]


def norm_ghsa(s):
    return "GHSA-" + s[5:].lower()


def norm_crate(n):
    return (n or "").lower().replace("-", "_")


def repo_of(url):
    m = REPO_URL_RE.fullmatch((url or "").strip())
    return (m.group(1).lower() + "/" + m.group(2).lower()) if m else ""


def load_rows(text):
    return list(csv.DictReader(io.StringIO(text or "")))


def check_rows(rows, expect=EXPECT):
    graded = [r for r in rows if r.get("status") == "NEITHER" and r.get("repo") != SEED_REPO
              and r.get("published") and r["published"] < CUTOFF]
    neither = sum(1 for r in rows if r.get("status") == "NEITHER")
    summary = {"rows": len(rows), "neither": neither, "graded": len(graded)}
    summary["ok"] = (len(rows), neither, len(graded)) == tuple(expect)
    return summary, graded


def load_records(zip_bytes):
    recs = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                recs.append(json.loads(zf.read(name).decode("utf-8")))
            except ValueError:
                continue
    return recs


def build_index(recs):
    """known: GHSA IDs OSV's export knows; cve: CVE -> [{id, packages}] from live RUSTSEC/reviewed GHSA."""
    idx = {"known": set(), "cve": {}, "rustsec_records": 0}
    for r in recs:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id", ""))
        live = not r.get("withdrawn")
        if rid.startswith("RUSTSEC-"):
            idx["rustsec_records"] += 1
            reviewed = True
            if live:
                for a in (r.get("aliases") or []) + (r.get("related") or []):
                    if isinstance(a, str) and a.upper().startswith("GHSA-"):
                        idx["known"].add(norm_ghsa(a))
        elif rid.startswith("GHSA-"):
            idx["known"].add(norm_ghsa(rid))
            reviewed = (r.get("database_specific") or {}).get("github_reviewed") is True
        else:
            continue
        if not (live and reviewed):
            continue
        pkgs = sorted({str((a.get("package") or {}).get("name") or "") for a in r.get("affected") or []
                       if isinstance(a, dict)} - {""})
        for a in r.get("aliases") or []:
            if isinstance(a, str) and a.upper().startswith("CVE-"):
                idx["cve"].setdefault(a.upper(), []).append({"id": rid, "packages": pkgs})
    return idx


def http_get(url, tries=4, sleep=time.sleep):
    """Return (status, final_url, text, headers with lower-case keys). Retries 5xx and network errors."""
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read().decode("utf-8", "replace")
                return resp.status, resp.geturl(), body, {k.lower(): v for k, v in resp.headers.items()}
        except urllib.error.HTTPError as exc:
            h = {k.lower(): v for k, v in (exc.headers or {}).items()}
            if exc.code >= 500 and i < tries - 1:
                sleep(5 * (i + 1))
                continue
            return exc.code, url, "", h
        except OSError:
            if i < tries - 1:
                sleep(5 * (i + 1))
    return 0, url, "", {}


def next_link(header):
    for part in (header or "").split(","):
        m = NEXT_RE.fullmatch(part)
        if m:
            return m.group(1)
    return None


def repo_api(repo, get, now, deadline, sleep):
    """Published repository advisories of one repo. Return (status, {ghsa: info})."""
    out = {}
    url = "https://api.github.com/repos/%s/security-advisories?state=published&per_page=100" % repo
    while url:
        code, _, text, hdrs = get(url)
        if code in (403, 429) and str(hdrs.get("x-ratelimit-remaining", "")) == "0":
            try:
                reset = int(hdrs.get("x-ratelimit-reset") or 0)
            except ValueError:
                reset = 0
            wait = max(5, reset - int(now()) + 5)
            if now() + wait > deadline:
                return "API_SKIPPED", out
            sleep(wait)
            continue
        if code != 200:
            return "API_FAILED", out
        try:
            arr = json.loads(text)
        except ValueError:
            return "API_FAILED", out
        for a in arr if isinstance(arr, list) else []:
            if not isinstance(a, dict):
                continue
            gid = a.get("ghsa_id")
            if not isinstance(gid, str) or not re.fullmatch(GHSA_PAT, gid, re.I):
                continue
            names, ranges = [], []
            for v in a.get("vulnerabilities") or []:
                if not isinstance(v, dict):
                    continue
                pkg = v.get("package") or {}
                if str(pkg.get("ecosystem") or "").lower() != "rust":
                    continue
                name = str(pkg.get("name") or "").strip()
                if not name:
                    continue
                if name not in names:
                    names.append(name)
                ranges.append("%s %s -> %s" % (name, v.get("vulnerable_version_range") or "?",
                                               v.get("patched_versions") or "none"))
            out[norm_ghsa(gid)] = {"cve_id": str(a.get("cve_id") or "").upper(),
                                   "withdrawn": bool(a.get("withdrawn_at")),
                                   "rust_packages": names, "ranges": ranges}
        url = next_link(hdrs.get("link", ""))
    return "OK", out


def osv_lookup(vid, get):
    """Return (status, crates.io package names) for one OSV ID."""
    code, _, text, _ = get("https://api.osv.dev/v1/vulns/" + vid)
    if code == 404:
        return "NOT_IN_OSV", []
    if code != 200:
        return "OSV_ERROR", []
    try:
        rec = json.loads(text)
    except ValueError:
        return "OSV_ERROR", []
    if not isinstance(rec, dict):
        return "OSV_ERROR", []
    if rec.get("withdrawn"):
        return "WITHDRAWN_IN_OSV", []
    pk = set()
    for a in rec.get("affected") or []:
        p = (a.get("package") or {}) if isinstance(a, dict) else {}
        if p.get("ecosystem") == "crates.io" and p.get("name"):
            pk.add(str(p["name"]))
    return "IN_OSV", sorted(pk)


def crate_variants(name):
    out = []
    low = name.lower()
    for v in (name, low, name.replace("_", "-"), name.replace("-", "_"), low.replace("_", "-"),
              low.replace("-", "_")):
        if v not in out:
            out.append(v)
    return out


def crate_lookup(name, get, sleep):
    res = {"name": name, "status": "NOT_FOUND", "canonical": "", "recent_downloads": "", "repository": ""}
    if not CRATE_RE.fullmatch(name or ""):
        res["status"] = "INVALID_NAME"
        return res
    for v in crate_variants(name):
        code, text = 0, ""
        for attempt in range(3):
            code, _, text, _ = get(CRATES_API + v)
            sleep(1.0)
            if code != 429:
                break
            sleep(30.0 * (attempt + 1))
        if code == 404:
            continue
        if code != 200:
            res["status"] = "ERROR"
            return res
        try:
            c = json.loads(text)["crate"]
            res.update(status="FOUND", canonical=str(c.get("name") or v),
                       recent_downloads=int(c.get("recent_downloads") or 0),
                       repository=str(c.get("repository") or ""))
        except (ValueError, KeyError, TypeError, AttributeError):
            res["status"] = "ERROR"
        return res
    return res


def classify(gid, info, idx, osv_ghsa, cve_osv, crates):
    """Return (status, covered_by, covering crate names)."""
    if info is None:
        return "API_MISSING", "", []
    if info.get("withdrawn"):
        return "WITHDRAWN", "", []
    if gid in idx["known"] or osv_ghsa == "IN_OSV":
        return "NOW_KNOWN", "", []
    if osv_ghsa == "OSV_ERROR":
        return "OSV_ERROR", "", []
    cve = info.get("cve_id") or ""
    if cve:
        hits = idx["cve"].get(cve) or []
        if hits:
            pk = sorted({p for h in hits for p in h["packages"]})
            return "CVE_COVERED", ";".join(sorted({h["id"] for h in hits})), pk
        st, pk = cve_osv or ("", [])
        if st == "IN_OSV" and pk:
            return "CVE_COVERED", cve, list(pk)
    looked = [crates.get(n) for n in info.get("rust_packages") or []]
    if any(c and c["status"] == "FOUND" for c in looked):
        return "ACTIONABLE", "", []
    if any(c is None or c["status"] == "ERROR" for c in looked):
        return "CRATE_ERROR", "", []
    return "NO_CRATE", "", []


def count_by(rows, key):
    out = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return dict(sorted(out.items()))


def share(a, b):
    return (a / b) if b else None


def grade(out):
    n = len(out)
    cnt = count_by(out, "status")
    act = cnt.get("ACTIONABLE", 0)
    cve_rows = [r for r in out if r["s18_cve"] == "yes"]
    no_cve = [r for r in out if r["s18_cve"] != "yes"]
    cov = sum(1 for r in cve_rows if r["status"] == "CVE_COVERED")
    act_no = sum(1 for r in no_cve if r["status"] == "ACTIONABLE")
    noc = cnt.get("NO_CRATE", 0)
    known = cnt.get("NOW_KNOWN", 0)
    preds = {
        "Q1_actionable_at_least_50pct": {"value": act, "of": n, "share": share(act, n),
                                         "held": (act >= 0.5 * n) if n else None},
        "Q2_cve_rows_covered_at_least_20pct": {"value": cov, "of": len(cve_rows), "share": share(cov, len(cve_rows)),
                                               "held": (cov >= 0.2 * len(cve_rows)) if cve_rows else None},
        "Q3_no_crate_5_to_35pct": {"value": noc, "of": n, "share": share(noc, n),
                                   "held": (0.05 * n <= noc <= 0.35 * n) if n else None},
        "Q4_no_cve_rows_actionable_at_least_70pct": {"value": act_no, "of": len(no_cve),
                                                     "share": share(act_no, len(no_cve)),
                                                     "held": (act_no >= 0.7 * len(no_cve)) if no_cve else None},
        "Q5_now_known_at_most_5pct": {"value": known, "of": n, "share": share(known, n),
                                      "held": (known <= 0.05 * n) if n else None},
        "Q6_hand_check": {"held": None, "note": "graded by hand from sample.csv: at least 7 of 8 confirmed"},
    }
    rng = random.Random(SEED)
    pool = sorted(r["ghsa_id"] for r in out if r["status"] == "ACTIONABLE")
    sample = sorted(rng.sample(pool, min(SAMPLE_N, len(pool))))
    return preds, sample


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def _dl(r):
    return r["max_recent_downloads"] if isinstance(r["max_recent_downloads"], int) else -1


def run(rows_text, idx, get, sleep, now, deadline, out_dir, provenance, expect=EXPECT,
        min_rustsec=GATE_MIN_RUSTSEC, log=None):
    os.makedirs(out_dir, exist_ok=True)
    integ, graded = check_rows(load_rows(rows_text), expect)
    result = {"version": __version__, "provenance": provenance, "rows_check": integ}
    if not integ["ok"]:
        result["gate"] = {"passed": False, "reason": "rows.csv does not match S18"}
        return _finish(result, out_dir)
    repos = sorted({r["repo"] for r in graded})
    api, repo_status = {}, {}
    for repo in repos:
        st, info = repo_api(repo, get, now, deadline, sleep)
        repo_status[repo] = st
        api.update(info)
        if log:
            log("%s %s %d" % (repo, st, len(info)))
        sleep(1.0)
    ids = [norm_ghsa(r["ghsa_id"]) for r in graded]
    osv_g = {}
    for gid in ids:
        if gid not in idx["known"] and gid not in osv_g:
            osv_g[gid] = osv_lookup(gid, get)[0]
            sleep(0.2)
    osv_c = {}
    for gid in ids:
        cve = (api.get(gid) or {}).get("cve_id", "")
        if cve and cve not in osv_c:
            osv_c[cve] = osv_lookup(cve, get)
            sleep(0.2)
    names = sorted({n for gid in ids for n in (api.get(gid) or {}).get("rust_packages", [])})
    crates = {n: crate_lookup(n, get, sleep) for n in names}
    controls = {"serde": crate_lookup("serde", get, sleep)["status"],
                NEG_CRATE: crate_lookup(NEG_CRATE, get, sleep)["status"]}
    out = []
    for r in graded:
        gid = norm_ghsa(r["ghsa_id"])
        info = api.get(gid)
        cve = (info or {}).get("cve_id", "")
        st, cov, cov_pk = classify(gid, info, idx, osv_g.get(gid, ""), osv_c.get(cve) if cve else None, crates)
        pk = (info or {}).get("rust_packages", [])
        found = [crates[n] for n in pk if n in crates and crates[n]["status"] == "FOUND"]
        dls = [c["recent_downloads"] for c in found if isinstance(c["recent_downloads"], int)]
        same = ""
        if st == "CVE_COVERED":
            same = "yes" if {norm_crate(x) for x in cov_pk} & {norm_crate(x) for x in pk} else "no"
        match = ""
        if found:
            match = "yes" if any(repo_of(c["repository"]) == r["repo"].lower() for c in found) else "no"
        out.append({"repo": r["repo"], "ghsa_id": gid, "published": r["published"], "severity": r["severity"],
                    "s18_cve": r["cve"], "cve_id": cve, "status": st, "covered_by": cov,
                    "covered_same_crate": same, "rust_packages": ";".join(pk),
                    "crates_found": ";".join(c["canonical"] for c in found), "repo_match": match,
                    "max_recent_downloads": max(dls) if dls else "",
                    "ranges": " | ".join((info or {}).get("ranges", []))})
    unresolved = sum(1 for o in out if o["status"] in UNRESOLVED)
    ok_repos = sum(1 for s in repo_status.values() if s == "OK")
    gate = {"rustsec_records": idx["rustsec_records"], "controls": controls, "repos": len(repos),
            "repos_ok": ok_repos, "rows": len(out), "unresolved": unresolved}
    gate["passed"] = bool(idx["rustsec_records"] >= min_rustsec and controls["serde"] == "FOUND"
                          and controls[NEG_CRATE] == "NOT_FOUND" and repos and ok_repos >= 0.9 * len(repos)
                          and unresolved <= 0.1 * len(out))
    result.update({"gate": gate, "status_counts": count_by(out, "status"),
                   "repo_api_status": count_by([{"s": s} for s in repo_status.values()], "s")})
    write_csv(os.path.join(out_dir, "s18b_rows.csv"), out, ROW_FIELDS)
    write_csv(os.path.join(out_dir, "crates.csv"), [crates[n] for n in names], CRATE_FIELDS)
    if gate["passed"]:
        preds, sample = grade(out)
        act = [o for o in out if o["status"] == "ACTIONABLE"]
        cov = [o for o in out if o["status"] == "CVE_COVERED"]
        git_only = sorted(c for c, v in osv_c.items() if v[0] == "IN_OSV" and not v[1])
        top = sorted(act, key=lambda o: (-_dl(o), o["ghsa_id"]))[:30]
        result.update({"predictions": preds, "sample": sample, "exploratory": {
            "actionable_by_severity": count_by(act, "severity"),
            "actionable_by_repo": count_by(act, "repo"),
            "actionable_repo_match": count_by(act, "repo_match"),
            "cve_covered_same_crate": count_by(cov, "covered_same_crate"),
            "cve_records_git_only": git_only,
            "top_actionable_by_recent_downloads": [
                {k: o[k] for k in ("repo", "ghsa_id", "severity", "published", "crates_found",
                                   "max_recent_downloads")} for o in top],
        }})
        write_csv(os.path.join(out_dir, "sample.csv"), [o for o in out if o["ghsa_id"] in sample], ROW_FIELDS)
    return _finish(result, out_dir)


def _finish(result, out_dir):
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as fh:
        fh.write(render(result))
    return result


def render(res):
    lines = ["# S18b job output (machine-written, not yet graded by hand)", "",
             "Script actionable_s18b.py %s. Made with AI agents working in MV2's (Munim, Inc.) name." % res["version"],
             "", "Provenance: `%s`" % json.dumps(res["provenance"], sort_keys=True), "",
             "rows.csv check: `%s`" % json.dumps(res["rows_check"], sort_keys=True), "",
             "Gate: %s (`%s`)" % ("PASSED" if res["gate"]["passed"] else "FAILED",
                                  json.dumps(res["gate"], sort_keys=True)), ""]
    if "status_counts" in res:
        lines += ["Status counts: `%s`" % json.dumps(res["status_counts"], sort_keys=True), ""]
    if res["gate"]["passed"]:
        lines += ["| prediction | result | held |", "|---|---|---|"]
        for k, v in res["predictions"].items():
            shown = {kk: vv for kk, vv in v.items() if kk != "held"}
            lines.append("| %s | `%s` | %s |" % (k, json.dumps(shown, sort_keys=True), v["held"]))
        lines += ["", "Exploratory (not predicted): `%s`" % json.dumps(res["exploratory"], sort_keys=True), "",
                  "Seeded hand-check sample (seed %d): %s" % (SEED, ", ".join(res["sample"]))]
    return "\n".join(lines) + "\n"


def fetch_rows(get, sleep, url=ROWS_URL, wait_min=60.0):
    """S18's rows.csv is published right after this job is filed, so poll for it."""
    tries = int(wait_min * 60 / 120) + 1
    for i in range(tries):
        code, _, text, _ = get(url)
        if code == 200 and text:
            return text
        if i < tries - 1:
            sleep(120)
    return None


def fetch_zip(url, dest, tries=4):
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
            with open(dest, "wb") as fh:
                fh.write(data)
            return data
        except OSError as exc:
            last = exc
            time.sleep(5 * (i + 1))
    raise SystemExit("download failed: %s" % last)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--data-dir", default="data")
    p.add_argument("--out-dir", default="out")
    p.add_argument("--rows", help="use this local S18 rows.csv instead of downloading it")
    p.add_argument("--zip", help="use this local OSV crates.io zip instead of downloading it")
    p.add_argument("--rows-wait-min", type=float, default=60.0)
    p.add_argument("--deadline-min", type=float, default=80.0, help="stop REST API waits after this many minutes")
    p.add_argument("--version", action="store_true")
    a = p.parse_args(argv)
    if a.version:
        print("actionable_s18b.py " + __version__)
        return 0
    os.makedirs(a.data_dir, exist_ok=True)
    if a.rows:
        with open(a.rows, encoding="utf-8") as fh:
            text = fh.read()
        rows_src = a.rows
    else:
        text = fetch_rows(http_get, time.sleep, ROWS_URL, a.rows_wait_min)
        rows_src = ROWS_URL
    if not text:
        print("S18 rows.csv not available")
        return 3
    start = time.time()
    fetched = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if a.zip:
        with open(a.zip, "rb") as fh:
            data = fh.read()
        zsrc = a.zip
    else:
        data = fetch_zip(ZIP_URL, os.path.join(a.data_dir, "crates-io-all-s18b-%s.zip" % fetched[:10]))
        zsrc = ZIP_URL
    prov = {"rows_source": rows_src, "rows_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "zip_source": zsrc, "zip_fetched_utc": fetched, "zip_bytes": len(data),
            "zip_sha256": hashlib.sha256(data).hexdigest()}
    idx = build_index(load_records(data))
    res = run(text, idx, http_get, time.sleep, time.time, start + 60 * a.deadline_min, a.out_dir, prov,
              log=lambda s: print(s, flush=True))
    print(render(res))
    return 0 if res["gate"]["passed"] else 3


if __name__ == "__main__":
    sys.exit(main())
