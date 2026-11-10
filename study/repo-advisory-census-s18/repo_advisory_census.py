#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""repo_advisory_census.py: Rust repository advisories that no scanner database carries.

Study S18 of https://github.com/munimtechnologies/advisory-import-census (pre-registered in
study/repo-advisory-census-s18/PREREG.md). Maintainers publish GitHub repository security
advisories on their own repositories. Dependabot reads only advisories that GitHub has reviewed into
its global Advisory Database; cargo-audit and cargo-deny read only RustSec; osv-scanner reads OSV,
which imports both. A published repository advisory for a crate that is in none of them is invisible
to all three.

Frame: every GitHub repository named in a ".../security/advisories/GHSA-..." reference of any record
in OSV's crates.io export. For each repository the public list of published advisories is read
(the HTML page, one request per page, about one per second). Each listed GHSA ID is looked up in the
export (GHSA records and RUSTSEC aliases). IDs not in the export are looked up in the OSV API; for
repositories with IDs that OSV does not know, the public REST endpoint for repository advisories is
read once (unauthenticated, 60 requests per hour) to get each advisory's ecosystem, severity,
publication date and CVE. No usernames, credits or other personal data are stored.

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

ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip"
CUTOFF = "2026-10-27"          # graded rows: published before this date (two weeks of review time)
SEED = 20261111
SAMPLE_N = 8
SEED_REPO = "zip-rs/zip2"      # seen by hand before pre-registration: reported, never graded
SEED_REPO_MIN_IDS = 30         # parser self-check: we counted 34 published advisories by hand
MAX_PAGES = 40
GATE_MIN_RUSTSEC = 500
GATE_MIN_REPOS = 100
GATE_MIN_IDS = 200
UA = "advisory-import-census-s18/%s (+https://github.com/munimtechnologies/advisory-import-census)" % __version__

GHSA_PAT = r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
NAME = r"[A-Za-z0-9_.-]+"
REF_RE = re.compile(r"https?://github\.com/(%s)/(%s)/security/advisories/(%s)(?:[/?#].*)?" % (NAME, NAME, GHSA_PAT), re.I)
HREF_RE = re.compile(r'href="(?:https://github\.com)?/(%s)/(%s)/security/advisories/(%s)"' % (NAME, NAME, GHSA_PAT), re.I)
FINAL_RE = re.compile(r"https?://github\.com/(%s)/(%s)/security/advisories(?:[/?#].*)?" % (NAME, NAME), re.I)
NEXT_RE = re.compile(r'\s*<([^>]+)>\s*;\s*rel="next"\s*')

RUST_STATUSES = ("BOTH", "RUSTSEC_ONLY", "GHSA_ONLY", "OSV_UNREVIEWED_ONLY", "OSV_NOT_IN_EXPORT", "NEITHER")


def norm_ghsa(s):
    return "GHSA-" + s[5:].lower()


def norm_repo(owner, repo):
    repo = repo[:-4] if repo.lower().endswith(".git") else repo
    return owner.lower() + "/" + repo.lower()


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


def _has_cve(rec):
    return any(isinstance(a, str) and a.upper().startswith("CVE-") for a in rec.get("aliases") or [])


def build_index(recs):
    """rustsec: GHSA id -> live RUSTSEC record info; ghsa: GHSA id -> record info; repos: repo -> ids."""
    idx = {"rustsec": {}, "ghsa": {}, "repos": {}, "rustsec_records": 0}
    for r in recs:
        rid = str(r.get("id", ""))
        withdrawn = bool(r.get("withdrawn"))
        if rid.startswith("RUSTSEC-"):
            idx["rustsec_records"] += 1
            if not withdrawn:
                for v in (r.get("aliases") or []) + (r.get("related") or []):
                    if isinstance(v, str) and v.upper().startswith("GHSA-"):
                        idx["rustsec"].setdefault(norm_ghsa(v), {
                            "id": rid, "published": (r.get("published") or "")[:10], "cve": _has_cve(r)})
        elif rid.startswith("GHSA-"):
            ds = r.get("database_specific") or {}
            idx["ghsa"][norm_ghsa(rid)] = {
                "reviewed": ds.get("github_reviewed") is True, "withdrawn": withdrawn,
                "published": (r.get("published") or "")[:10], "severity": ds.get("severity") or "",
                "cve": _has_cve(r)}
        for ref in r.get("references") or []:
            url = ref.get("url", "") if isinstance(ref, dict) else ""
            m = REF_RE.fullmatch(url or "")
            if m:
                idx["repos"].setdefault(norm_repo(m.group(1), m.group(2)), set()).add(norm_ghsa(m.group(3)))
    return idx


def parse_list_page(html):
    ids = []
    for m in HREF_RE.finditer(html or ""):
        g = norm_ghsa(m.group(3))
        if g not in ids:
            ids.append(g)
    return ids


def next_link(header):
    for part in (header or "").split(","):
        m = NEXT_RE.fullmatch(part)
        if m:
            return m.group(1)
    return None


def http_get(url, tries=4, sleep=time.sleep, accept=None):
    """Return (status, final_url, text, headers with lower-case keys). Retries 5xx and network errors."""
    hdrs = {"User-Agent": UA}
    if accept:
        hdrs["Accept"] = accept
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=hdrs)
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


def list_repo(repo, get, sleep, max_pages=MAX_PAGES):
    """Read the published-advisory list of one repository. Return (status, canonical repo, ids)."""
    ids, canonical = [], repo
    for page in range(1, max_pages + 1):
        url = "https://github.com/%s/security/advisories?state=published&page=%d" % (repo, page)
        code, final, text = 0, url, ""
        for attempt in range(4):
            code, final, text, _ = get(url)
            if code != 429:
                break
            sleep(60 * (attempt + 1))
        if code == 404:
            return ("REPO_404" if page == 1 else "OK"), canonical, ids
        if code != 200:
            return "FETCH_FAILED", canonical, ids
        if page == 1:
            m = FINAL_RE.fullmatch(final or "")
            if m:
                canonical = norm_repo(m.group(1), m.group(2))
        new = [g for g in parse_list_page(text) if g not in ids]
        if not new:
            return "OK", canonical, ids
        ids.extend(new)
        sleep(1.0)
    return "PAGE_LIMIT", canonical, ids


def osv_lookup(gid, get):
    code, _, text, _ = get("https://api.osv.dev/v1/vulns/" + gid)
    if code == 404:
        return "NOT_IN_OSV", []
    if code != 200:
        return "OSV_ERROR", []
    try:
        rec = json.loads(text)
    except ValueError:
        return "OSV_ERROR", []
    ecos = set()
    for a in rec.get("affected") or []:
        if isinstance(a, dict):
            e = (a.get("package") or {}).get("ecosystem") or ""
            if e:
                ecos.add(e)
    return "IN_OSV", sorted(ecos)


def repo_api(repo, get, now, deadline, sleep):
    """Published repository advisories of one repo via the public REST API. Return (status, {id: info})."""
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
            gid = a.get("ghsa_id") if isinstance(a, dict) else None
            if not isinstance(gid, str) or not re.fullmatch(GHSA_PAT, gid, re.I):
                continue
            ecos, names = set(), set()
            for v in a.get("vulnerabilities") or []:
                pkg = (v.get("package") or {}) if isinstance(v, dict) else {}
                if pkg.get("ecosystem"):
                    ecos.add(str(pkg["ecosystem"]).lower())
                if pkg.get("name"):
                    names.add(str(pkg["name"]))
            out[norm_ghsa(gid)] = {
                "severity": a.get("severity") or "", "published": (a.get("published_at") or "")[:10],
                "cve": bool(a.get("cve_id")), "withdrawn": bool(a.get("withdrawn_at")),
                "ecosystems": sorted(ecos), "packages": sorted(names)}
        url = next_link(hdrs.get("link", ""))
    return "OK", out


def norm_sev(s):
    s = (s or "").upper()
    return "MODERATE" if s == "MEDIUM" else s


def classify(gid, idx, osv=None, api=None):
    """Return the status of one listed advisory. osv = (status, ecosystems); api = info dict or None."""
    rs = gid in idx["rustsec"]
    gh = idx["ghsa"].get(gid)
    if gh and gh["withdrawn"] and not rs:
        return "WITHDRAWN"
    reviewed = bool(gh and gh["reviewed"] and not gh["withdrawn"])
    unreviewed = bool(gh and not gh["reviewed"] and not gh["withdrawn"])
    if rs and reviewed:
        return "BOTH"
    if rs:
        return "RUSTSEC_ONLY"
    if reviewed:
        return "GHSA_ONLY"
    if unreviewed:
        return "OSV_UNREVIEWED_ONLY"
    status, ecos = osv or ("OSV_ERROR", [])
    if status == "IN_OSV":
        return "OSV_NOT_IN_EXPORT" if "crates.io" in ecos else "OTHER_ECOSYSTEM"
    if status != "NOT_IN_OSV":
        return "OSV_ERROR"
    if api is None:
        return "UNKNOWN_ECOSYSTEM"
    if api["withdrawn"]:
        return "WITHDRAWN"
    if "rust" in api["ecosystems"]:
        return "NEITHER"
    if not api["ecosystems"]:
        return "NO_PACKAGE"
    return "OTHER_ECOSYSTEM"


def make_row(repo, gid, idx, osv, api):
    gh = idx["ghsa"].get(gid) or {}
    rs = idx["rustsec"].get(gid) or {}
    a = api or {}
    return {
        "repo": repo, "ghsa_id": gid, "status": classify(gid, idx, osv, api),
        "published": a.get("published") or gh.get("published") or rs.get("published") or "",
        "severity": norm_sev(a.get("severity") or gh.get("severity") or ""),
        "cve": "yes" if (a.get("cve") or gh.get("cve") or rs.get("cve")) else "no",
        "rustsec_id": rs.get("id", ""),
        "ghsa_reviewed": "yes" if gh.get("reviewed") else ("no" if gh else ""),
        "osv": (osv or ("", []))[0],
        "ecosystems": ";".join(a.get("ecosystems") or (osv or ("", []))[1]),
        "packages": ";".join(a.get("packages") or []),
    }


ROW_FIELDS = ["repo", "ghsa_id", "status", "published", "severity", "cve", "rustsec_id", "ghsa_reviewed",
              "osv", "ecosystems", "packages"]
REPO_FIELDS = ["repo", "canonical", "status", "listed", "api"]


def grade(rows, repo_rows):
    graded = [r for r in rows if r["repo"] != SEED_REPO and r["status"] in RUST_STATUSES
              and r["published"] and r["published"] < CUTOFF]
    neither = [r for r in graded if r["status"] == "NEITHER"]
    n = len(neither)
    repos = sorted({r["repo"] for r in neither})

    def share(sub):
        return (sum(1 for r in sub if r["status"] == "NEITHER") / len(sub)) if sub else None
    with_cve = [r for r in graded if r["cve"] == "yes"]
    no_cve = [r for r in graded if r["cve"] == "no"]
    s_cve, s_no = share(with_cve), share(no_cve)
    p3 = None
    if s_no is not None and len(no_cve) >= 10 and s_cve is not None:
        p3 = (s_no > 0 and s_cve == 0) or (s_cve > 0 and s_no >= 3 * s_cve)
    high = sum(1 for r in neither if r["severity"] in ("HIGH", "CRITICAL"))
    listable = [r for r in repo_rows if r["status"] not in ("REPO_404", "DUPLICATE")]
    ok = sum(1 for r in listable if r["status"] == "OK")
    preds = {
        "P1_neither_at_least_20": {"value": n, "held": n >= 20},
        "P2_neither_repos_at_least_5": {"value": len(repos), "held": len(repos) >= 5},
        "P3_no_cve_share_at_least_3x_cve_share": {
            "no_cve": {"n": len(no_cve), "share": s_no}, "cve": {"n": len(with_cve), "share": s_cve}, "held": p3},
        "P4_high_or_critical_share_at_least_25pct": {
            "value": high, "of": n, "share": (high / n) if n else None, "held": (high / n >= 0.25) if n else None},
        "P5_listing_ok_at_least_90pct": {
            "value": ok, "of": len(listable), "share": (ok / len(listable)) if listable else None,
            "held": (ok / len(listable) >= 0.90) if listable else None},
        "P6_hand_check": {"held": None, "note": "graded by hand from sample.csv: at least 7 of 8 confirmed"},
    }
    rng = random.Random(SEED)
    pool = sorted(r["ghsa_id"] for r in neither)
    sample = sorted(rng.sample(pool, min(SAMPLE_N, len(pool))))
    return graded, neither, preds, sample


def count_by(rows, key):
    out = {}
    for r in rows:
        out[r[key]] = out.get(r[key], 0) + 1
    return dict(sorted(out.items()))


def write_csv(path, rows, fields):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def census(idx, get, sleep, now, deadline, max_repos=0, log=None):
    """Run the listing, OSV and API steps. Return (rows, repo_rows)."""
    frame = sorted(idx["repos"])
    if max_repos:
        frame = frame[:max_repos]
    listed, repo_rows, by_canon = {}, [], {}
    for repo in frame:
        status, canon, ids = list_repo(repo, get, sleep)
        if canon in by_canon:
            repo_rows.append({"repo": repo, "canonical": canon, "status": "DUPLICATE", "listed": 0, "api": ""})
            continue
        by_canon[canon] = len(repo_rows)
        listed[canon] = ids
        repo_rows.append({"repo": repo, "canonical": canon, "status": status, "listed": len(ids), "api": ""})
        if log:
            log("%s %s %d" % (canon, status, len(ids)))
    osv = {}
    for canon, ids in listed.items():
        for gid in ids:
            if gid not in idx["rustsec"] and gid not in idx["ghsa"] and gid not in osv:
                osv[gid] = osv_lookup(gid, get)
                sleep(0.2)
    api = {}
    for canon, ids in listed.items():
        if any(osv.get(g, ("",))[0] == "NOT_IN_OSV" for g in ids):
            st, info = repo_api(canon, get, now, deadline, sleep)
            repo_rows[by_canon[canon]]["api"] = st
            api.update(info)
            sleep(1.0)
    rows = []
    for canon, ids in listed.items():
        for gid in ids:
            rows.append(make_row(canon, gid, idx, osv.get(gid), api.get(gid)))
    return rows, repo_rows


def run(idx, out_dir, provenance, get, sleep, now, deadline, max_repos=0, min_repos=GATE_MIN_REPOS,
        min_ids=GATE_MIN_IDS, min_rustsec=GATE_MIN_RUSTSEC, log=None):
    os.makedirs(out_dir, exist_ok=True)
    rows, repo_rows = census(idx, get, sleep, now, deadline, max_repos, log)
    seed_ids = sum(1 for r in rows if r["repo"] == SEED_REPO)
    seed_in_frame = any(r["canonical"] == SEED_REPO for r in repo_rows)
    gate = {"rustsec_records": idx["rustsec_records"], "frame_repos": len(repo_rows), "listed_ids": len(rows),
            "seed_repo_ids": seed_ids, "seed_in_frame": seed_in_frame}
    gate["passed"] = (idx["rustsec_records"] >= min_rustsec and len(repo_rows) >= min_repos
                      and len(rows) >= min_ids and (not seed_in_frame or seed_ids >= SEED_REPO_MIN_IDS))
    result = {"version": __version__, "provenance": provenance, "gate": gate,
              "status_counts": count_by(rows, "status"), "repo_status_counts": count_by(repo_rows, "status")}
    write_csv(os.path.join(out_dir, "rows.csv"), rows, ROW_FIELDS)
    write_csv(os.path.join(out_dir, "repos.csv"), repo_rows, REPO_FIELDS)
    seed_rows = [r for r in rows if r["repo"] == SEED_REPO]
    result["seed_repo"] = {"repo": SEED_REPO, "listed": len(seed_rows), "status_counts": count_by(seed_rows, "status")}
    if gate["passed"]:
        graded, neither, preds, sample = grade(rows, repo_rows)
        result.update({"graded_rows": len(graded), "neither": len(neither), "predictions": preds, "sample": sample,
                       "exploratory": {
                           "graded_status_counts": count_by(graded, "status"),
                           "neither_by_severity": count_by(neither, "severity"),
                           "neither_by_repo": count_by(neither, "repo"),
                           "neither_by_month": count_by([dict(r, month=r["published"][:7]) for r in neither], "month"),
                           "all_neither_any_date": sum(1 for r in rows if r["status"] == "NEITHER"),
                       }})
        write_csv(os.path.join(out_dir, "sample.csv"), [r for r in neither if r["ghsa_id"] in sample], ROW_FIELDS)
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as fh:
        fh.write(render(result))
    return result


def render(res):
    lines = ["# S18 job output (machine-written, not yet graded by hand)", "",
             "Script repo_advisory_census.py %s. Made with AI agents working in MV2's (Munim, Inc.) name." % res["version"],
             "", "Provenance: `%s`" % json.dumps(res["provenance"], sort_keys=True), "",
             "Gate: %s (`%s`)" % ("PASSED" if res["gate"]["passed"] else "FAILED", json.dumps(res["gate"], sort_keys=True)),
             "", "Status counts (all rows): `%s`" % json.dumps(res["status_counts"], sort_keys=True),
             "", "Repository listing: `%s`" % json.dumps(res["repo_status_counts"], sort_keys=True),
             "", "Seed repository (not graded): `%s`" % json.dumps(res["seed_repo"], sort_keys=True), ""]
    if res["gate"]["passed"]:
        lines += ["Graded rows (Rust, published before %s, seed repository excluded): %d; NEITHER: %d"
                  % (CUTOFF, res["graded_rows"], res["neither"]), "", "| prediction | result | held |", "|---|---|---|"]
        for k, v in res["predictions"].items():
            shown = {kk: vv for kk, vv in v.items() if kk != "held"}
            lines.append("| %s | `%s` | %s |" % (k, json.dumps(shown, sort_keys=True), v["held"]))
        lines += ["", "Exploratory (not predicted): `%s`" % json.dumps(res["exploratory"], sort_keys=True), "",
                  "Seeded hand-check sample (seed %d): %s" % (SEED, ", ".join(res["sample"]))]
    return "\n".join(lines) + "\n"


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
    p.add_argument("--zip", help="use this local zip instead of downloading")
    p.add_argument("--max-repos", type=int, default=0, help="0 = whole frame")
    p.add_argument("--deadline-min", type=float, default=150.0, help="stop REST API waits after this many minutes")
    p.add_argument("--version", action="store_true")
    a = p.parse_args(argv)
    if a.version:
        print("repo_advisory_census.py " + __version__)
        return 0
    start = time.time()
    os.makedirs(a.data_dir, exist_ok=True)
    fetched = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if a.zip:
        with open(a.zip, "rb") as fh:
            data = fh.read()
        src = a.zip
    else:
        data = fetch_zip(ZIP_URL, os.path.join(a.data_dir, "crates-io-all-s18-%s.zip" % fetched[:10]))
        src = ZIP_URL
    prov = {"source": src, "fetched_utc": fetched, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    idx = build_index(load_records(data))
    res = run(idx, a.out_dir, prov, http_get, time.sleep, time.time, start + 60 * a.deadline_min,
              max_repos=a.max_repos, log=lambda s: print(s, flush=True))
    print(render(res))
    return 0 if res["gate"]["passed"] else 3


if __name__ == "__main__":
    sys.exit(main())
