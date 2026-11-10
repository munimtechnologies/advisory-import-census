# SPDX-License-Identifier: Apache-2.0
# Offline tests for osv_fix_followup.py (fixtures only, no network).
# Made with AI agents working for MV2 of Munim, Inc.
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import osv_fix_followup as p  # noqa: E402

HEADER = ("cve,stratum,assigner,published,rejected,osv_status,osv_modified,osv_withdrawn,"
          "other_aliases,osv_ecosystems\n")


def frame_text(live, withdrawn, other=0):
    lines = [HEADER]
    for c in live:
        lines.append("%s,R1,VulnCheck,2026-08-25T15:15:53,2026-09-08T14:57:43,LIVE,,,,GIT\n" % c)
    for c in withdrawn:
        lines.append("%s,R3,Wordfence,2025-07-01T00:00:00,2025-07-24T00:00:00,WITHDRAWN,,,,\n" % c)
    for i in range(other):
        lines.append("CVE-2020-%05d,R3,mitre,,,NOT_FOUND,,,,\n" % i)
    return "".join(lines)


def rec(cve, withdrawn=None, aliases=(), rid=None):
    o = {"id": rid or cve, "modified": "2026-11-12T01:02:03.456Z", "aliases": list(aliases)}
    if withdrawn:
        o["withdrawn"] = withdrawn
    return 200, json.dumps(o).encode()


class Frame(unittest.TestCase):
    def test_load(self):
        t = frame_text(["CVE-2026-1001", "CVE-2026-1002"], ["CVE-2025-3848"], other=3)
        t += "not-a-cve,R1,x;rm,,,LIVE,,,,\n"
        t += "CVE-2026-1003,R1,Bad Name<script>,,2026-09-01T00:00:00,LIVE,,,,\n"
        live, wd, n = p.load_frame(t)
        self.assertEqual(n, 8)
        self.assertEqual([r["cve"] for r in live], ["CVE-2026-1001", "CVE-2026-1002",
                                                    "CVE-2026-1003"])
        self.assertEqual(live[2]["assigner"], "BadNamescript")
        self.assertEqual([r["cve"] for r in wd], ["CVE-2025-3848"])


class Lookup(unittest.TestCase):
    def test_states(self):
        db = {
            p.OSV + "CVE-2026-1001": rec("CVE-2026-1001",
                                         aliases=["GHSA-aaaa-bbbb-cccc", "bad alias!"]),
            p.OSV + "CVE-2026-1002": rec("CVE-2026-1002", withdrawn="2026-11-12T00:00:00Z"),
            p.OSV + "CVE-2026-1003": (404, b""),
            p.OSV + "CVE-2026-1004": rec("CVE-2026-1004", rid="CVE-2026-9999"),
            p.OSV + "CVE-2026-1005": rec("CVE-2026-1005", withdrawn="yesterday"),
        }
        with mock.patch.object(p.time, "sleep"):
            f = lambda u: db[u]  # noqa: E731
            a = p.lookup(f, "CVE-2026-1001")
            self.assertEqual(a["status"], "LIVE")
            self.assertEqual(a["aliases"], ["GHSA-aaaa-bbbb-cccc"])
            self.assertEqual(p.lookup(f, "CVE-2026-1002")["status"], "WITHDRAWN")
            self.assertEqual(p.lookup(f, "CVE-2026-1003")["status"], "NOT_FOUND")
            self.assertEqual(p.lookup(f, "CVE-2026-1004")["status"], "ERROR")
            self.assertEqual(p.lookup(f, "CVE-2026-1005")["status"], "LIVE")
        with self.assertRaises(ValueError):
            p.lookup(lambda u: (404, b""), "CVE-x/../../")

    def test_retry_then_success(self):
        calls = []

        def f(u):
            calls.append(u)
            if len(calls) == 1:
                raise urllib.error.URLError("down")
            return rec("CVE-2026-1007")
        with mock.patch.object(p.time, "sleep"):
            self.assertEqual(p.lookup(f, "CVE-2026-1007")["status"], "LIVE")
        self.assertEqual(len(calls), 2)

    def test_bad_json_is_error(self):
        with mock.patch.object(p.time, "sleep"):
            self.assertEqual(p.lookup(lambda u: (200, b"{nope"), "CVE-2026-1008")["status"],
                             "ERROR")
            self.assertEqual(p.lookup(lambda u: (503, b""), "CVE-2026-1008")["status"], "ERROR")

    def test_allow_list(self):
        for url in ("https://evil.example/", "https://raw.githubusercontent.com/other/repo/x",
                    "http://api.osv.dev/v1/vulns/CVE-2026-1"):
            with self.assertRaises(ValueError):
                p.http_get(url)


def st(status, withdrawn="", aliases=()):
    return {"status": status, "modified": "", "withdrawn": withdrawn, "aliases": list(aliases)}


class Grade(unittest.TestCase):
    def setUp(self):
        self.live = {c: st("WITHDRAWN", "2026-11-12T00:00:00Z") for c in p.HAND}
        for i in range(94):
            self.live["CVE-2026-%d" % (200000 + i)] = st("WITHDRAWN", "2026-11-12T00:00:00Z")
        self.wd = {"CVE-2025-3848": st("WITHDRAWN", "2025-07-26T00:00:00Z")}
        self.pairs = {"CVE-2026-106571": st("LIVE", aliases=["GHSA-jvjm-9f73-fhpq"]),
                      "CVE-2026-56397": st("LIVE", aliases=["GO-2026-4720"])}

    def test_all_hold(self):
        gate, counts, pr = p.grade(self.live, self.wd, self.pairs)
        self.assertTrue(gate["passed"])
        self.assertEqual(counts["WITHDRAWN"], 100)
        for k in ("P1", "P2", "P3", "P4", "P5", "P6"):
            self.assertIs(pr[k]["held"], True, k)

    def test_fix_not_deployed(self):
        live = {c: st("LIVE") for c in self.live}
        pairs = {"CVE-2026-106571": st("LIVE", aliases=["CVE-2026-105398"]),
                 "CVE-2026-56397": st("LIVE", aliases=["CVE-2026-56395"])}
        _, _, pr = p.grade(live, self.wd, pairs)
        self.assertIs(pr["P1"]["held"], False)
        self.assertEqual(pr["P1"]["value"], 0.0)
        self.assertIs(pr["P2"]["held"], False)   # nothing left LIVE -> no share
        self.assertIsNone(pr["P2"]["value"])
        self.assertIs(pr["P3"]["held"], False)
        self.assertIs(pr["P5"]["held"], False)
        self.assertIs(pr["P6"]["held"], False)

    def test_thresholds(self):
        live = dict(self.live)
        for c in list(live)[90:]:          # 10 of 100 still LIVE -> 90% gone (holds)
            live[c] = st("LIVE")
        for c in list(live)[:20]:          # 20 removed (404) instead of withdrawn
            live[c] = st("NOT_FOUND")
        _, _, pr = p.grade(live, self.wd, self.pairs)
        self.assertAlmostEqual(pr["P1"]["value"], 0.90)
        self.assertIs(pr["P1"]["held"], True)
        self.assertAlmostEqual(pr["P2"]["value"], 70 / 90)
        self.assertIs(pr["P2"]["held"], False)
        self.assertIs(pr["P3"]["held"], True)   # NOT_FOUND counts as no longer live

    def test_old_withdrawn_dates_fail_p6(self):
        live = dict(self.live)
        for c in list(live)[:6]:
            live[c] = st("WITHDRAWN", "2026-11-09T23:59:59Z")
        _, _, pr = p.grade(live, self.wd, self.pairs)
        self.assertAlmostEqual(pr["P6"]["value"], 0.94)
        self.assertIs(pr["P6"]["held"], False)

    def test_inconclusive_and_gate(self):
        live = dict(self.live)
        live[p.HAND[0]] = st("ERROR")
        pairs = {"CVE-2026-106571": st("NOT_FOUND"), "CVE-2026-56397": st("LIVE")}
        wd = {"CVE-2025-3848": st("ERROR")}
        gate, _, pr = p.grade(live, wd, pairs)
        self.assertIsNone(pr["P3"]["held"])
        self.assertIsNone(pr["P4"]["held"])
        self.assertIsNone(pr["P5"]["held"])
        self.assertTrue(gate["passed"])        # 2 errors of 103 lookups
        many = {c: st("ERROR") for c in list(self.live)[:10]}
        live.update(many)
        gate, _, _ = p.grade(live, wd, pairs)
        self.assertFalse(gate["passed"])

    def test_control_regression_fails_p4(self):
        _, _, pr = p.grade(self.live, {"CVE-2025-3848": st("LIVE")}, self.pairs)
        self.assertIs(pr["P4"]["held"], False)


class EndToEnd(unittest.TestCase):
    def test_run(self):
        live_ids = list(p.HAND) + ["CVE-2026-300001"]
        db = {p.FRAME_URL: (200, frame_text(live_ids, ["CVE-2025-3848"], other=2).encode())}
        for c in live_ids:
            db[p.OSV + c] = rec(c, withdrawn="2026-11-13T00:00:00Z")
        db[p.OSV + "CVE-2025-3848"] = (404, b"")
        db[p.OSV + "CVE-2026-106571"] = rec("CVE-2026-106571", aliases=["GHSA-jvjm-9f73-fhpq"])
        db[p.OSV + "CVE-2026-56397"] = rec("CVE-2026-56397", aliases=["CVE-2026-56395"])
        out = tempfile.mkdtemp()
        with mock.patch.object(p, "EXPECTED", {"rows": 10, "LIVE": 7, "WITHDRAWN": 1}), \
                mock.patch.object(p.time, "sleep"):
            code = p.main(["--out-dir", out], fetch=lambda u: db[u])
        self.assertEqual(code, 0)
        with open(os.path.join(out, "results.json"), encoding="utf-8") as f:
            res = json.load(f)
        self.assertTrue(res["graded"])
        self.assertEqual(res["s16_live_now"]["WITHDRAWN"], 7)
        self.assertIs(res["predictions"]["P1"]["held"], True)
        self.assertIs(res["predictions"]["P5"]["held"], False)
        self.assertEqual(res["by_stratum"], {"R1": {"WITHDRAWN": 7}})
        with open(os.path.join(out, "rows.csv"), encoding="utf-8") as f:
            self.assertEqual(len(f.read().strip().splitlines()), 9)

    def test_frame_mismatch_stops(self):
        db = {p.FRAME_URL: (200, frame_text(["CVE-2026-1001"], []).encode())}
        out = tempfile.mkdtemp()
        self.assertEqual(p.main(["--out-dir", out], fetch=lambda u: db[u]), 3)
        with open(os.path.join(out, "results.json"), encoding="utf-8") as f:
            self.assertFalse(json.load(f)["graded"])


if __name__ == "__main__":
    unittest.main()
