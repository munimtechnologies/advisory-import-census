#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).
"""S17: did google/osv.dev#6314 withdraw the rejected 2026 CVEs that study S16 found live?

Reads S16's frozen sample (study/osv-cve-withdrawn-s16/job-v1/rows.csv in this repository),
looks up every CVE that S16 graded LIVE (163) or WITHDRAWN (7) once more at
api.osv.dev/v1/vulns/<CVE>, plus the two replacement CVEs whose records listed a rejected
duplicate as an alias, and grades the six predictions frozen in PREREG.md.

Writes rows.csv (one row per CVE), results.json (counts, gate, predictions) and RESULTS-job.md.
Read-only; standard library only. Exit 0 when graded, 3 when the frame or the gate fails.
"""
import argparse
import csv
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

UA = "advisory-import-census/s17 (mv2@munimtech.com)"
FRAME_URL = ("https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/main/"
             "study/osv-cve-withdrawn-s16/job-v1/rows.csv")
OSV = "https://api.osv.dev/v1/vulns/"
ALLOWED = (OSV, "https://raw.githubusercontent.com/munimtechnologies/advisory-import-census/")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T[0-9:.]+Z?$")
EXPECTED = {"rows": 1392, "LIVE": 163, "WITHDRAWN": 7}
HAND = ["CVE-2026-104040", "CVE-2026-105398", "CVE-2026-119717", "CVE-2026-56395",
        "CVE-2026-78154", "CVE-2026-97618"]
PAIRS = [("CVE-2026-105398", "CVE-2026-106571"), ("CVE-2026-56395", "CVE-2026-56397")]
FIX_MERGED = "2026-11-10"
MAX_ERROR_SHARE = 0.05


def http_get(url):
    """(status, body bytes); HTTP errors return their status with an empty body."""
    if not url.startswith(ALLOWED):
        raise ValueError("host not allowed: " + url[:80])
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read(20_000_000)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def load_frame(text):
    """S16 rows -> (live rows, withdrawn rows, total rows). Only validated fields are kept."""
    rows = list(csv.DictReader(io.StringIO(text)))
    live, wd = [], []
    for r in rows:
        cve = r.get("cve") or ""
        if not CVE_RE.match(cve):
            continue
        keep = {"cve": cve, "stratum": (r.get("stratum") or "")[:4],
                "assigner": re.sub(r"[^A-Za-z0-9_.-]", "", r.get("assigner") or "")[:40],
                "rejected": (r.get("rejected") or "")[:19]}
        if r.get("osv_status") == "LIVE":
            live.append(keep)
        elif r.get("osv_status") == "WITHDRAWN":
            wd.append(keep)
    return live, wd, len(rows)


def lookup(fetch, cve, retries=1):
    """Current OSV.dev state of one record: status LIVE / WITHDRAWN / NOT_FOUND / ERROR."""
    if not CVE_RE.match(cve):
        raise ValueError("bad CVE id")
    out = {"status": "ERROR", "modified": "", "withdrawn": "", "aliases": []}
    for attempt in range(retries + 1):
        try:
            code, body = fetch(OSV + cve)
        except (urllib.error.URLError, OSError, ValueError):
            code, body = None, b""
        if code == 404:
            return dict(out, status="NOT_FOUND")
        if code == 200:
            try:
                obj = json.loads(body.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                obj = None
            if isinstance(obj, dict) and obj.get("id") == cve:
                mod = obj.get("modified")
                wd = obj.get("withdrawn")
                aliases = [a for a in (obj.get("aliases") or [])
                           if isinstance(a, str) and re.match(r"^[A-Za-z0-9:._-]{1,80}$", a)]
                out = {"status": "LIVE", "aliases": sorted(aliases),
                       "modified": mod if isinstance(mod, str) and TS_RE.match(mod) else "",
                       "withdrawn": wd if isinstance(wd, str) and TS_RE.match(wd) else ""}
                if out["withdrawn"]:
                    out["status"] = "WITHDRAWN"
                return out
        if attempt < retries:
            time.sleep(2)
    return out


def share(n, d):
    return (n / d) if d else None


def grade(live_now, wd_now, pair_now):
    """live_now / wd_now: {cve: lookup result} for S16's LIVE and WITHDRAWN rows;
    pair_now: {replacement cve: lookup result}. Returns (gate, counts, predictions)."""
    total = len(live_now) + len(wd_now) + len(pair_now)
    errors = sum(1 for d in (live_now, wd_now, pair_now) for r in d.values()
                 if r["status"] == "ERROR")
    gate = {"lookups": total, "errors": errors,
            "passed": total > 0 and errors <= MAX_ERROR_SHARE * total}
    ok = [r for r in live_now.values() if r["status"] != "ERROR"]
    gone = [r for r in ok if r["status"] in ("WITHDRAWN", "NOT_FOUND")]
    wd = [r for r in ok if r["status"] == "WITHDRAWN"]
    counts = {s: sum(1 for r in live_now.values() if r["status"] == s)
              for s in ("LIVE", "WITHDRAWN", "NOT_FOUND", "ERROR")}
    preds = {}

    s1 = share(len(gone), len(ok))
    preds["P1"] = {"value": s1, "n": len(ok), "held": s1 is not None and s1 >= 0.90}
    s2 = share(len(wd), len(gone))
    preds["P2"] = {"value": s2, "n": len(gone), "held": s2 is not None and s2 >= 0.80}
    hand = [live_now.get(c, {"status": "ERROR"})["status"] for c in HAND]
    if "ERROR" in hand:
        preds["P3"] = {"value": hand, "held": None}
    else:
        preds["P3"] = {"value": hand, "held": all(s != "LIVE" for s in hand)}
    ctrl = [r["status"] for r in wd_now.values()]
    if "ERROR" in ctrl:
        preds["P4"] = {"value": ctrl, "held": None}
    else:
        preds["P4"] = {"value": ctrl, "held": all(s in ("WITHDRAWN", "NOT_FOUND") for s in ctrl)}
    p5, p5_ok = [], True
    for rejected, repl in PAIRS:
        r = pair_now.get(repl, {"status": "ERROR", "aliases": []})
        if r["status"] != "LIVE":
            p5_ok = None if p5_ok is not False else False
            p5.append({"replacement": repl, "status": r["status"], "lists_rejected": None})
            continue
        listed = rejected in r["aliases"]
        p5.append({"replacement": repl, "status": "LIVE", "lists_rejected": listed})
        if listed:
            p5_ok = False
    preds["P5"] = {"value": p5, "held": p5_ok}
    after = [r for r in wd if r["withdrawn"][:10] >= FIX_MERGED]
    s6 = share(len(after), len(wd))
    preds["P6"] = {"value": s6, "n": len(wd), "held": s6 is not None and s6 >= 0.95}
    return gate, counts, preds


def run(fetch, out_dir):
    code, body = fetch(FRAME_URL)
    if code != 200:
        raise SystemExit("frame download failed: HTTP %s" % code)
    live, wdrows, n = load_frame(body.decode("utf-8"))
    frame = {"rows": n, "LIVE": len(live), "WITHDRAWN": len(wdrows)}
    os.makedirs(out_dir, exist_ok=True)
    if frame != EXPECTED:
        with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
            json.dump({"frame": frame, "expected": EXPECTED, "graded": False}, f, indent=1)
        return 3
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    live_now = {r["cve"]: lookup(fetch, r["cve"]) for r in live}
    wd_now = {r["cve"]: lookup(fetch, r["cve"]) for r in wdrows}
    pair_now = {repl: lookup(fetch, repl) for _rej, repl in PAIRS}
    gate, counts, preds = grade(live_now, wd_now, pair_now)
    with open(os.path.join(out_dir, "rows.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve", "group", "stratum", "assigner", "rejected", "status_s16",
                    "status_now", "modified", "withdrawn"])
        for group, src, now in (("s16_live", live, live_now), ("s16_withdrawn", wdrows, wd_now)):
            for r in src:
                x = now[r["cve"]]
                w.writerow([r["cve"], group, r["stratum"], r["assigner"], r["rejected"],
                            "LIVE" if group == "s16_live" else "WITHDRAWN",
                            x["status"], x["modified"], x["withdrawn"]])
    by_stratum = {}
    for r in live:
        k = r["stratum"]
        by_stratum.setdefault(k, {}).setdefault(live_now[r["cve"]]["status"], 0)
        by_stratum[k][live_now[r["cve"]]["status"]] += 1
    res = {"graded": gate["passed"], "started": started,
           "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "frame": frame, "gate": gate, "s16_live_now": counts, "by_stratum": by_stratum,
           "predictions": preds}
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    lines = ["# S17 job output", "", "Lookups %s to %s UTC. Gate: %d lookups, %d errors, %s." % (
        started, res["finished"], gate["lookups"], gate["errors"],
        "passed" if gate["passed"] else "FAILED"), "",
        "S16 LIVE records now: " + ", ".join("%s %d" % kv for kv in counts.items()), ""]
    for k in sorted(preds):
        lines.append("- %s: held=%s value=%s" % (k, preds[k]["held"],
                                                  json.dumps(preds[k]["value"])))
    with open(os.path.join(out_dir, "RESULTS-job.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    sys.stdout.write("\n".join(lines) + "\n")
    return 0 if gate["passed"] else 3


def main(argv=None, fetch=http_get):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    return run(fetch, args.out_dir)


if __name__ == "__main__":
    sys.exit(main())
