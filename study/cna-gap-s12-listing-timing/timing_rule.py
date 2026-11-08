# S12: is a CVE kept out of GitHub's Advisory Database when a repository advisory listing it already exists
# when NVD publishes it? Part of advisory-import-census.
# Copyright 2026 Munim, Inc. Licensed under the Apache License, Version 2.0.
# Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com). Stdlib only.
"""Reads S11's published frame (the S10 frame rebuilt at advisory-database commit b072a703) and S11's sample, takes
CVEs from CNAs other than GitHub and VulnCheck whose cited repository advisory is not a global advisory and that S11
did NOT sample, fetches each cited repository advisory page once, and records its "CVE ID" field and its published
time. Grades the frozen predictions in PREREG.md."""

import argparse
import csv
import hashlib
import html
import io
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request

BASE = "https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main/study/cna-gap-s11-repo-cve-field/"
FRAME_URLS = [BASE + "frame-part-1.csv", BASE + "frame-part-2.csv"]
S11_ROWS_URL = BASE + "rows.csv"
V2_ROWS_URL = BASE + "v2-gate-failed/rows.csv"  # pages fetched by S11's failed v2 run: also excluded
V2_ROWS = 180
PREREG_URL = ("https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main/"
              "study/cna-gap-s12-listing-timing/PREREG.md")
FRAME_SHA256 = "819b43ea612c80725c5aada9055a745346953e5db9e79940624dce550349e323"
FRAME_ROWS = 18102
S11_STRATA = {"OV_COV": 1273, "OV_UNC": 122, "OO_COV": 287, "OO_UNC": 876, "G_UNC": 5913, "G_COV": 16}
S11_ROWS = 266
SEED = 20261108
UNC_SAMPLE = 200
VULNCHECK = "disclosure@vulncheck.com"
COVERED = {"REVIEWED", "UNREVIEWED_ONLY"}
UNCOVERED = {"NONE", "WITHDRAWN_ONLY"}
UA = "advisory-import-census S12 (research; mv2@munimtech.com)"
MIN_PARSED = 30
MIN_CELL = 10

# Parser checks, all read by hand on 2026-11-07/08 (S11); none of them can be sampled here.
KNOWN = [
    ("Cap-go", "capgo", "GHSA-6g74-8cpq-g2c8", "CVE-2026-56243", "NO_CVE", ""),
    ("OneUptime", "oneuptime", "GHSA-g9cp-35m2-fjv6", "CVE-2026-45102", "LISTS_THIS", ""),
    ("zephyrproject-rtos", "zephyr", "GHSA-hfww-j92m-x8fv", "CVE-2024-10395", "LISTS_THIS", ""),
    ("zammad", "zammad", "GHSA-p97w-927q-8vxq", "CVE-2026-102490", "LISTS_THIS", "2026-10-08"),
    ("chamilo", "chamilo-lms", "GHSA-hvpp-6mp9-frx4", "CVE-2025-50193", "LISTS_THIS", "2026-03-02"),
    ("rabbitmq", "rabbitmq-server", "GHSA-9wm4-9m6g-w38x", "CVE-2026-66068", "LISTS_THIS", "2026-07-09"),
]
# The eight S11 hand-read advisories are excluded from every draw (as in S11).
S11_KNOWN_GHSA = {"GHSA-6g74-8cpq-g2c8", "GHSA-v527-r4px-7vx7", "GHSA-g9cp-35m2-fjv6", "GHSA-35fr-6rv9-vp68",
                  "GHSA-g65h-9ggq-9827", "GHSA-rwp7-7vc6-8477", "GHSA-hfww-j92m-x8fv", "GHSA-2wvh-87g2-89hr"}

# Same page parsing as S11's repo_cve.py.
CVE_FIELD = re.compile(r"CVE ID\s+(No known CVE|CVE-\d{4}-\d{4,})")
REL_TIME = re.compile(r'<relative-time[^>]*datetime="([^"]+)"')
TAGS = re.compile(r"<[^>]+>")
SCRIPTS = re.compile(r"<(script|style)\b.*?</\1>", re.S | re.I)
WS = re.compile(r"\s+")
DAY = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def page_text(raw):
    t = SCRIPTS.sub(" ", raw)
    t = TAGS.sub(" ", t)
    return WS.sub(" ", html.unescape(t)).strip()


def classify(raw, cve):
    """(state, listed_cve, published) for one repository advisory page."""
    m = CVE_FIELD.search(page_text(raw))
    if not m:
        state, listed = "UNPARSED", ""
    elif m.group(1) == "No known CVE":
        state, listed = "NO_CVE", ""
    elif m.group(1) == cve:
        state, listed = "LISTS_THIS", m.group(1)
    else:
        state, listed = "LISTS_OTHER", m.group(1)
    rt = REL_TIME.search(raw)
    return state, listed, (rt.group(1) if rt else "")


def timing(adv_published, nvd_published):
    """EARLY if the advisory was published on or before NVD's publication day (UTC days), LATE if after,
    NODATE if either date is missing."""
    a, n = DAY.match(adv_published or ""), DAY.match(nvd_published or "")
    if not a or not n:
        return "NODATE"
    return "EARLY" if a.group(1) <= n.group(1) else "LATE"


def stratum(row):
    """OO_COV / OO_UNC for arm O, CNA not VulnCheck, cited advisory NOT_GLOBAL; else None."""
    if row.get("arm") != "O" or row.get("source") == VULNCHECK or row.get("ref_global_state") != "NOT_GLOBAL":
        return None
    cov = row.get("coverage", "")
    if cov in COVERED:
        return "OO_COV"
    if cov in UNCOVERED:
        return "OO_UNC"
    return None


def s11_strata_sizes(rows):
    """S11's six strata, recomputed, as a check that the frame is S11's."""
    out = {k: 0 for k in S11_STRATA}
    for r in rows:
        if r.get("ref_global_state") != "NOT_GLOBAL":
            continue
        cov = r.get("coverage", "")
        c = "COV" if cov in COVERED else ("UNC" if cov in UNCOVERED else None)
        if c is None:
            continue
        if r.get("arm") == "G":
            out["G_" + c] += 1
        elif r.get("arm") == "O":
            out[("OV_" if r.get("source") == VULNCHECK else "OO_") + c] += 1
    return out


def join_parts(parts):
    """Rebuild the frame text from parts that each repeat the header line."""
    if not parts:
        return ""
    header = parts[0].split("\n", 1)[0] + "\n"
    text = parts[0]
    for p in parts[1:]:
        if not p.startswith(header):
            raise ValueError("part does not start with the frame header")
        text += p[len(header):]
    return text


def frame_sha(text, want=FRAME_SHA256):
    """sha256 of the frame text. S11 wrote it with csv's CRLF line ends; if the served copy has LF line ends only,
    the sha256 is also taken after restoring CRLF (same content). Returns (sha256, which)."""
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if sha == want:
        return sha, "as served"
    alt = hashlib.sha256(text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8")).hexdigest()
    if alt == want:
        return alt, "line endings restored to CRLF"
    return sha, "as served"


def pools(rows, s11_cves):
    """Rows per stratum that S11 did not sample and that are not hand-read cases, sorted by CVE ID."""
    by = {"OO_COV": [], "OO_UNC": []}
    for r in rows:
        s = stratum(r)
        if s and r["cve"] not in s11_cves and r["ref_ghsa"] not in S11_KNOWN_GHSA:
            by[s].append(r)
    for k in by:
        by[k].sort(key=lambda r: r["cve"])
    return by


def draw(by, seed=SEED, unc_n=UNC_SAMPLE):
    rng = random.Random(seed)
    return {"OO_COV": list(by["OO_COV"]),
            "OO_UNC": rng.sample(by["OO_UNC"], min(unc_n, len(by["OO_UNC"])))}


def cells(results):
    """Per stratum: counts of NO_CVE, LISTS_OTHER, LISTS_THIS by timing, UNPARSED, GONE, ERROR."""
    keys = ["NO_CVE", "LISTS_OTHER", "LT_EARLY", "LT_LATE", "LT_NODATE", "UNPARSED", "GONE", "ERROR"]
    out = {}
    for r in results:
        d = out.setdefault(r["stratum"], {k: 0 for k in keys})
        if r["state"] == "LISTS_THIS":
            d["LT_" + r["timing"]] += 1
        else:
            d[r["state"]] += 1
    return out


def parsed(d):
    return d["NO_CVE"] + d["LISTS_OTHER"] + d["LT_EARLY"] + d["LT_LATE"] + d["LT_NODATE"]


def est(d, size, key):
    """Estimated number of CVEs in the stratum's pool in cell `key` (size x share of parsed pages)."""
    p = parsed(d)
    return size * d[key] / p if p else 0.0


def cov_share(c, sizes, key):
    """Estimated covered share among the pool's CVEs in cell `key`, weighted by pool size.
    Returns [covered_est, total_est, percent, raw_pages]."""
    cv = est(c["OO_COV"], sizes["OO_COV"], key) if "OO_COV" in c else 0.0
    un = est(c["OO_UNC"], sizes["OO_UNC"], key) if "OO_UNC" in c else 0.0
    raw = sum(c[s][key] for s in c)
    tot = cv + un
    return [round(cv, 1), round(tot, 1), round(100.0 * cv / tot, 1) if tot else None, raw]


def rule_accuracy(c, sizes):
    """Rule: uncovered iff the page lists this CVE and was published on or before NVD's day.
    Weighted share of parsed, dated pages where the rule is right."""
    right = tot = 0.0
    for s, d in c.items():
        p = parsed(d) - d["LT_NODATE"]
        if not p:
            continue
        ok = d["LT_EARLY"] if s == "OO_UNC" else d["NO_CVE"] + d["LISTS_OTHER"] + d["LT_LATE"]
        right += sizes[s] * ok / p
        tot += sizes[s]
    return [round(right, 1), round(tot, 1), round(100.0 * right / tot, 1) if tot else None]


def grade(c, sizes):
    v = {}
    enough = all(s in c and parsed(c[s]) >= MIN_PARSED for s in ("OO_COV", "OO_UNC"))

    def judge(val, lo=None, hi=None, min_raw=MIN_CELL):
        if not enough or val[2] is None or (len(val) > 3 and val[3] < min_raw):
            return "inconclusive"
        if lo is not None and val[2] < lo:
            return "no"
        if hi is not None and val[2] > hi:
            return "no"
        return "yes"

    t1 = cov_share(c, sizes, "LT_EARLY")
    v["T1"] = {"claim": "Lists this CVE and published on or before NVD's day: covered share <= 12%", "value": t1,
               "held": judge(t1, hi=12)}
    t2 = cov_share(c, sizes, "LT_LATE")
    v["T2"] = {"claim": "Lists this CVE and published after NVD's day: covered share >= 75%", "value": t2,
               "held": judge(t2, lo=75)}
    t3 = cov_share(c, sizes, "NO_CVE")
    v["T3"] = {"claim": "Says No known CVE: covered share >= 80%", "value": t3, "held": judge(t3, lo=80)}

    def late_share(s):
        d = c.get(s)
        if not d:
            return [0, 0, None, 0]
        n = d["LT_EARLY"] + d["LT_LATE"]
        return [d["LT_LATE"], n, round(100.0 * d["LT_LATE"] / n, 1) if n else None, n]

    t4 = late_share("OO_UNC")
    v["T4"] = {"claim": "OO_UNC: <= 5% of dated listing pages were published after NVD's day", "value": t4,
               "held": judge(t4, hi=5)}
    t5 = late_share("OO_COV")
    v["T5"] = {"claim": "OO_COV: >= 40% of dated listing pages were published after NVD's day", "value": t5,
               "held": judge(t5, lo=40)}
    t6 = rule_accuracy(c, sizes)
    v["T6"] = {"claim": "The timing rule is right for >= 88% of CVEs (pool-weighted)", "value": t6,
               "held": judge(t6, lo=88)}
    return v


def gate_checks(fsha, n_rows, strata, s11_n, results, known_ok, v2_n=V2_ROWS):
    sampled = list(results)
    n = len(sampled)
    errors = sum(1 for r in sampled if r["state"] == "ERROR")
    ok200 = [r for r in sampled if r["http"] == 200]
    unparsed = sum(1 for r in ok200 if r["state"] == "UNPARSED")
    lt = [r for r in ok200 if r["state"] == "LISTS_THIS"]
    nodate = sum(1 for r in lt if r["timing"] == "NODATE")
    g = {
        "frame_sha256": fsha == FRAME_SHA256,
        "rows": n_rows == FRAME_ROWS,
        "strata": strata == S11_STRATA,
        "s11_sample": s11_n == S11_ROWS and v2_n == V2_ROWS,
        "errors": n > 0 and errors <= 0.05 * n,
        "parse": len(ok200) > 0 and unparsed <= 0.05 * len(ok200),
        "dates": nodate <= 0.05 * max(1, len(lt)),
        "known": known_ok,
    }
    return all(g.values()), g


def fetch(url, tries=4):
    """GET a page. Returns (http_status, text). 404 -> (404, ''); network error -> (0, '')."""
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and i < tries - 1:
                time.sleep(60 * (i + 1))
                continue
            return e.code, ""
        except Exception:
            if i < tries - 1:
                time.sleep(20)
                continue
            return 0, ""
    return 0, ""


def wait_for(url, starts, wait_minutes):
    deadline = time.time() + 60 * wait_minutes
    while True:
        code, text = fetch(url, tries=2)
        if code == 200 and text.startswith(starts):
            return text
        if time.time() > deadline:
            sys.exit("not available: %s (last HTTP %s)" % (url, code))
        print("waiting for %s (HTTP %s)" % (url, code), flush=True)
        time.sleep(120)


def adv_url(owner, repo, ghsa):
    return "https://github.com/%s/%s/security/advisories/%s" % (owner, repo, ghsa)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--wait-minutes", type=int, default=240)
    ap.add_argument("--delay", type=float, default=2.5)
    a = ap.parse_args()
    os.makedirs(a.out_dir, exist_ok=True)

    # No page is fetched before this pre-registration is public.
    wait_for(PREREG_URL, "# S12", a.wait_minutes)
    parts = [wait_for(u, "cve,", a.wait_minutes) for u in FRAME_URLS]
    text = join_parts(parts)
    fsha, sha_how = frame_sha(text)
    rows = list(csv.DictReader(io.StringIO(text)))
    strata = s11_strata_sizes(rows)
    s11 = list(csv.DictReader(io.StringIO(wait_for(S11_ROWS_URL, "stratum,", a.wait_minutes))))
    v2 = list(csv.DictReader(io.StringIO(wait_for(V2_ROWS_URL, "stratum,", a.wait_minutes))))
    s11_cves = {r["cve"] for r in s11} | {r["cve"] for r in v2}
    by = pools(rows, s11_cves)
    sizes = {k: len(v) for k, v in by.items()}
    picked = draw(by)
    print("frame sha256 %s (%s) rows %d strata %s pools %s" % (fsha, sha_how, len(rows), strata, sizes),
          flush=True)

    known_res = []
    for owner, repo, ghsa, cve, want, day in KNOWN:
        code, raw = fetch(adv_url(owner, repo, ghsa))
        st, _, pub = classify(raw, cve) if code == 200 else ("GONE" if code == 404 else "ERROR", "", "")
        known_res.append({"ghsa": ghsa, "want": want, "got": st, "want_day": day, "got_time": pub})
        time.sleep(a.delay)
    known_ok = all(k["got"] == k["want"] and (not k["want_day"] or k["got_time"][:10] == k["want_day"])
                   for k in known_res)

    results = []
    for s in ("OO_COV", "OO_UNC"):
        for r in picked[s]:
            code, raw = fetch(adv_url(r["ref_owner"], r["ref_repo"], r["ref_ghsa"]))
            if code == 200:
                st, listed, pub = classify(raw, r["cve"])
            else:
                st, listed, pub = ("GONE" if code == 404 else "ERROR"), "", ""
            results.append({"stratum": s, "cve": r["cve"], "source": r["source"], "coverage": r["coverage"],
                            "nvd_published": r["published"], "ref_owner": r["ref_owner"],
                            "ref_repo": r["ref_repo"], "ref_ghsa": r["ref_ghsa"], "http": code, "state": st,
                            "listed_cve": listed, "adv_published": pub,
                            "timing": timing(pub, r["published"]) if st == "LISTS_THIS" else ""})
            time.sleep(a.delay)
        print("stratum %s done (%d)" % (s, len(picked[s])), flush=True)

    passed, g = gate_checks(fsha, len(rows), strata, len(s11), results, known_ok, v2_n=len(v2))
    c = cells(results)
    verdicts = grade(c, sizes) if passed else {}
    by_cna = {}
    for r in results:
        if r["state"] == "LISTS_THIS":
            k = "%s|%s|%s" % (r["source"], r["stratum"], r["timing"])
            by_cna[k] = by_cna.get(k, 0) + 1
    res = {"frame_sha256": fsha, "frame_sha256_how": sha_how, "rows": len(rows), "s11_strata": strata, "pools": sizes,
           "sampled": {k: len(v) for k, v in picked.items()}, "seed": SEED,
           "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "gate_passed": passed, "gate": g,
           "known": known_res, "cells": c, "verdicts": verdicts,
           "descriptive": {"listing_by_cna_stratum_timing": dict(sorted(by_cna.items(), key=lambda x: -x[1])[:40])}}
    with open(os.path.join(a.out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    with open(os.path.join(a.out_dir, "rows.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()) if results else ["stratum"])
        w.writeheader()
        w.writerows(results)
    lines = ["# S12: does a repository advisory that lists the CVE before NVD publishes it keep the NVD-fed record "
             "out? (job output)", "",
             "Frame sha256 %s; rows %d; pools %s; sampled %s; run %s." % (fsha, len(rows), json.dumps(sizes),
                                                                         json.dumps(res["sampled"]), res["run_at"]),
             "", "Gate: %s %s" % ("PASSED" if passed else "FAILED", json.dumps(g)), "",
             "Known cases: %s" % json.dumps(known_res), ""]
    if passed:
        lines += ["| Prediction | Claim | Value | Held |", "|---|---|---|---|"]
        for k in sorted(verdicts):
            lines.append("| %s | %s | %s | %s |" % (k, verdicts[k]["claim"], json.dumps(verdicts[k]["value"]),
                                                    verdicts[k]["held"]))
        lines.append("")
    lines.append("Cells: %s" % json.dumps(c))
    with open(os.path.join(a.out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("done: gate %s %s" % (passed, json.dumps(g)), flush=True)


if __name__ == "__main__":
    main()
