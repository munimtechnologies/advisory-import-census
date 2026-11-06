"""Offline tests for backfill_rate.py (S9a). Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import csv
import json
import os
import tempfile
import unittest

import backfill_rate as br

COLS = ["cve", "published", "nvd_status", "coverage", "holders", "ref_owner", "ref_repo", "ref_ghsa",
        "ref_global_state", "uncovered_kind"]

# GHSA IDs use only the real GHSA alphabet (23456789cfghjmpqrvwx).
A_THIS_LATE = "GHSA-2222-3333-4444"     # lists this CVE; CVE published 10 days later       -> late, listed
A_NONE_JUNE = "GHSA-5555-6666-7777"     # lists nothing; published 2026-06-19; CVE 06-25     -> late, MISSING
A_THIS_SAME = "GHSA-cccc-ffff-gggg"     # lists this CVE; same day                           -> not late
A_NONE_LONG = "GHSA-hhhh-jjjj-mmmm"     # lists nothing; 2025-03-01, CVE 2025-05-01          -> late, MISSING, lag 61
A_OTHER = "GHSA-pppp-qqqq-rrrr"         # lists another CVE                                  -> LISTS_OTHER
A_WD = "GHSA-vvvv-wwww-xxxx"            # withdrawn                                          -> REF_WITHDRAWN
A_BUNDLE = "GHSA-2c2c-3f3f-4g4g"        # lists nothing, cited by two CVEs                   -> not eligible
A_ELSE = "GHSA-5h5h-6j6j-7m7m"          # lists nothing, CVE held by another reviewed advisory
A_MULTI = "GHSA-8p8p-9q9q-2r2r"         # lists this CVE and another                         -> LISTS_THIS_AND_OTHERS
A_MISSING_FILE = "GHSA-3v3v-4w4w-5x5x"  # not in the clone                                   -> REF_NOT_REVIEWED


def adv(gid, aliases, published, modified=None, withdrawn=""):
    return {"schema_version": "1.4.0", "id": gid, "published": published, "modified": modified or published,
            "withdrawn": withdrawn, "aliases": aliases,
            "database_specific": {"github_reviewed_at": published}}


class S9aTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = os.path.join(self.tmp.name, "advisories", "github-reviewed", "2026", "06")
        advs = [
            adv(A_THIS_LATE, ["CVE-2026-10001"], "2026-03-01T10:00:00Z", "2026-03-12T08:00:00Z"),
            adv(A_NONE_JUNE, [], "2026-06-19T16:36:11Z"),
            adv(A_THIS_SAME, ["CVE-2026-10003"], "2026-04-02T10:00:00Z"),
            adv(A_NONE_LONG, [], "2025-03-01T10:00:00Z"),
            adv(A_OTHER, ["CVE-2026-19999"], "2026-04-02T10:00:00Z"),
            adv(A_WD, [], "2026-04-02T10:00:00Z", withdrawn="2026-05-01T00:00:00Z"),
            adv(A_BUNDLE, [], "2026-04-02T10:00:00Z"),
            adv(A_ELSE, [], "2026-04-02T10:00:00Z"),
            adv(A_MULTI, ["CVE-2026-10009", "CVE-2026-10010"], "2026-04-02T10:00:00Z"),
        ]
        for a in advs:
            d = os.path.join(root, a["id"])
            os.makedirs(d)
            with open(os.path.join(d, a["id"] + ".json"), "w", encoding="utf-8") as f:
                json.dump(a, f)
        self.db = self.tmp.name
        rows = [
            ["CVE-2026-10001", "2026-03-11", "Analyzed", "REVIEWED", A_THIS_LATE + ":reviewed", "o", "r",
             A_THIS_LATE, "REVIEWED", ""],
            ["CVE-2026-10002", "2026-06-25", "Analyzed", "NONE", "", "o", "r", A_NONE_JUNE.upper(), "REVIEWED",
             "GLOBAL_WITHOUT_ALIAS"],
            ["CVE-2026-10003", "2026-04-02", "Analyzed", "REVIEWED", A_THIS_SAME + ":reviewed", "o", "r",
             A_THIS_SAME, "REVIEWED", ""],
            ["CVE-2025-10004", "2025-05-01", "Analyzed", "NONE", "", "o", "r", A_NONE_LONG, "REVIEWED",
             "GLOBAL_WITHOUT_ALIAS"],
            ["CVE-2026-10005", "2026-04-09", "Analyzed", "NONE", "", "o", "r", A_OTHER, "REVIEWED",
             "GLOBAL_WITHOUT_ALIAS"],
            ["CVE-2026-10006", "2026-04-09", "Analyzed", "WITHDRAWN_ONLY", "", "o", "r", A_WD,
             "REVIEWED_WITHDRAWN", "GLOBAL_WITHOUT_ALIAS"],
            ["CVE-2026-10007", "2026-04-09", "Analyzed", "NONE", "", "o", "r", A_BUNDLE, "REVIEWED",
             "GLOBAL_WITHOUT_ALIAS"],
            ["CVE-2026-10017", "2026-04-09", "Analyzed", "NONE", "", "o", "r", A_BUNDLE, "REVIEWED",
             "GLOBAL_WITHOUT_ALIAS"],
            ["CVE-2026-10008", "2026-04-09", "Analyzed", "REVIEWED", "GHSA-9999-9999-9999:reviewed", "o", "r",
             A_ELSE, "REVIEWED", ""],
            ["CVE-2026-10009", "2026-04-09", "Analyzed", "REVIEWED", A_MULTI + ":reviewed", "o", "r", A_MULTI,
             "REVIEWED", ""],
            ["CVE-2026-10011", "2026-04-09", "Analyzed", "NONE", "", "o", "r", A_MISSING_FILE, "NOT_GLOBAL",
             "REPO_ONLY"],
            ["CVE-2026-10012", "2026-04-09", "Analyzed", "NONE", "", "", "", "", "", "NO_REPO_ADVISORY_REF"],
        ]
        self.cves = os.path.join(self.tmp.name, "cves.csv")
        with open(self.cves, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(COLS)
            w.writerows(rows)
        self.rows = br.read_cves(self.cves)
        self.files = br.index_files(os.path.join(self.db, "advisories", "github-reviewed"))
        self.out = br.classify_rows(self.rows, self.files)
        self.by = {r["cve"]: r for r in self.out}

    def tearDown(self):
        self.tmp.cleanup()

    def test_norm_ghsa(self):
        self.assertEqual(br.norm_ghsa("GHSA-ABCD-EFGH-JKMP"), "GHSA-abcd-efgh-jkmp")
        self.assertEqual(br.norm_ghsa(""), "")

    def test_lag_days(self):
        self.assertEqual(br.lag_days("2026-06-19T16:36:11Z", "2026-06-25"), 6)
        self.assertEqual(br.lag_days("2026-06-19T23:59:59Z", "2026-06-19"), 0)
        self.assertIsNone(br.lag_days("", "2026-06-19"))

    def test_statuses(self):
        expect = {"CVE-2026-10001": "LISTS_THIS", "CVE-2026-10002": "LISTS_NONE", "CVE-2026-10003": "LISTS_THIS",
                  "CVE-2025-10004": "LISTS_NONE", "CVE-2026-10005": "LISTS_OTHER",
                  "CVE-2026-10006": "REF_WITHDRAWN", "CVE-2026-10007": "LISTS_NONE",
                  "CVE-2026-10008": "LISTS_NONE_HELD_ELSEWHERE", "CVE-2026-10009": "LISTS_THIS_AND_OTHERS",
                  "CVE-2026-10011": "REF_NOT_REVIEWED", "CVE-2026-10012": "NO_REF"}
        for cve, st in expect.items():
            self.assertEqual(self.by[cve]["status"], st, cve)

    def test_eligibility_and_late(self):
        el = sorted(r["cve"] for r in self.out if r["eligible"] == "yes")
        self.assertEqual(el, ["CVE-2025-10004", "CVE-2026-10001", "CVE-2026-10002", "CVE-2026-10003"])
        self.assertEqual(self.by["CVE-2026-10007"]["bundle_size"], 2)
        self.assertEqual(self.by["CVE-2026-10001"]["late"], "yes")
        self.assertEqual(self.by["CVE-2026-10001"]["lag_days"], 10)
        self.assertEqual(self.by["CVE-2026-10003"]["late"], "no")
        self.assertEqual(self.by["CVE-2025-10004"]["lag_days"], 61)
        self.assertEqual(self.by["CVE-2026-10001"]["modified_on_or_after_cve"], "yes")
        self.assertEqual(self.by["CVE-2026-10002"]["missing"], "yes")

    def test_grade(self):
        p = {x["id"]: x for x in br.grade(self.out)}
        # late eligible: 10001 (listed, lag 10), 10002 (missing, June batch, lag 6), 10004 (missing, lag 61)
        self.assertEqual(p["P1"]["value"][:2], [2, 3])
        self.assertFalse(p["P1"]["held"])
        self.assertEqual(p["P2"]["value"][:2], [1, 1])
        self.assertTrue(p["P2"]["held"])
        self.assertEqual(p["P3"]["value"][:2], [1, 2])  # 10001 (2026-03, listed) and 10004 (2025-03, missing)
        self.assertFalse(p["P3"]["held"])
        self.assertEqual(p["P4"]["value"]["lag_ge_30"][:2], [1, 1])
        self.assertEqual(p["P4"]["value"]["lag_1_29"][:2], [1, 2])
        self.assertTrue(p["P4"]["held"])
        self.assertEqual(p["P5"]["value"][:2], [3, 4])
        self.assertFalse(p["P5"]["held"])
        self.assertEqual(p["P6"]["value"][:2], [1, 1])
        self.assertTrue(p["P6"]["held"])

    def test_empty_groups_do_not_hold(self):
        p = {x["id"]: x for x in br.grade([])}
        self.assertFalse(any(x["held"] for x in p.values()))

    def test_gate_and_outputs(self):
        desc = br.describe(self.rows, self.out)
        self.assertEqual(desc["population_rows"], 12)
        self.assertEqual(desc["eligible_missing"], 2)
        ok, checks = br.gate(desc, {"rows": 12, "reviewed": 4, "global_without_alias": 6}, (2, 2))
        self.assertTrue(ok, checks)
        ok2, _ = br.gate(desc)
        self.assertFalse(ok2)
        out_dir = os.path.join(self.tmp.name, "out")
        meta = {"db_head": "x", "cves_source": self.cves, "cves_sha256": br.sha256(self.cves), "read_at": "t",
                "reviewed_files_indexed": len(self.files)}
        br.write_outputs(out_dir, self.out, br.grade(self.out), desc, ok, checks, meta)
        with open(os.path.join(out_dir, "rows.csv"), encoding="utf-8") as f:
            got = list(csv.DictReader(f))
        self.assertEqual(len(got), 10)  # NO_REF and REF_NOT_REVIEWED rows left out
        with open(os.path.join(out_dir, "RESULTS-job.md"), encoding="utf-8") as f:
            self.assertIn("Gate: PASSED", f.read())
        self.assertEqual(desc["late_by_adv_month_missing_of_n"]["2026-06"], [1, 1])
        self.assertEqual(desc["late_by_lag_days"]["30-89"][:2], [1, 1])


if __name__ == "__main__":
    unittest.main()
