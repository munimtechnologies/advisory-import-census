"""Offline tests for reserve_timing.py (S9c). Apache-2.0. Made with AI agents working for MV2 of Munim, Inc."""
import datetime
import json
import os
import tempfile
import unittest

import reserve_timing as rt

HEADER = ("cve,nvd_published,ref_owner,ref_repo,ref_ghsa,status,bundle_size,eligible,missing,adv_published,"
          "adv_modified,adv_reviewed_at,lag_days,late,modified_on_or_after_cve")
LINES = [
    # MISSING, reserved after review (pypdf shape)
    "CVE-2026-57204,2026-06-30,py-pdf,pypdf,GHSA-jm82-fx9c-mx94,LISTS_NONE,1,yes,yes,2026-06-18T14:28:49Z,"
    "2026-06-18T14:28:50Z,2026-06-18T14:28:49Z,12,yes,no",
    # MISSING, reserved before review, CNA source is another GHSA (laravel shape)
    "CVE-2026-48019,2026-09-04,laravel,framework,GHSA-5vg9-5847-vvmq,LISTS_NONE,1,yes,yes,2026-06-17T13:53:44Z,"
    "2026-06-17T13:53:44Z,2026-06-17T13:53:44Z,79,yes,no",
    # LISTED, reserved before review (chisel shape)
    "CVE-2026-48113,2026-08-03,jpillora,chisel,GHSA-24fp-5v3p-rvpw,LISTS_THIS,1,yes,no,2026-06-12T15:04:37Z,"
    "2026-06-12T15:04:37Z,2026-06-12T15:04:37Z,52,yes,no",
    # LISTED, reserved after review, file modified later (backfilled)
    "CVE-2025-55300,2025-08-18,komari-monitor,komari,GHSA-q355-h244-969h,LISTS_THIS,1,yes,no,2025-08-12T00:13:28Z,"
    "2025-08-20T09:00:00Z,2025-08-12T00:13:28Z,6,yes,yes",
    # not late: excluded from the population
    "CVE-2026-25800,2026-07-23,quinn-rs,quinn,GHSA-4w2j-m93h-cj5j,LISTS_NONE,1,yes,yes,2026-07-24T14:07:54Z,"
    "2026-07-24T14:07:54Z,2026-07-24T14:07:54Z,-1,no,yes",
    # not eligible: excluded
    "CVE-2026-95848,2026-10-01,moquette-io,moquette,GHSA-5f42-97gr-vfhq,LISTS_OTHER,7,no,no,2026-09-01T00:00:00Z,"
    "2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,30,yes,no",
]


def rec(reserved, source, refs, state="PUBLISHED", published="2026-07-01T00:00:00.000Z"):
    return {"state": state, "reserved": reserved, "published": published, "source_ghsa": source, "ref_ghsas": refs}


RECS = {
    "CVE-2026-57204": ("OK", rec("2026-06-24T02:00:46.801Z", "GHSA-jm82-fx9c-mx94", ["GHSA-jm82-fx9c-mx94"])),
    "CVE-2026-48019": ("OK", rec("2026-05-20T17:44:09.587Z", "GHSA-fpqx-6722-p65v", ["GHSA-5vg9-5847-vvmq"])),
    "CVE-2026-48113": ("OK", rec("2026-05-20T18:46:58.289Z", "GHSA-24fp-5v3p-rvpw", ["GHSA-24fp-5v3p-rvpw"])),
    "CVE-2025-55300": ("OK", rec("2025-08-12T16:15:30.238Z", "GHSA-q355-h244-969h", ["GHSA-q355-h244-969h"])),
}


def rows():
    return rt.read_rows_text("\n".join([HEADER] + LINES) + "\n")


class TestAmendment(unittest.TestCase):
    def test_constants(self):
        # AMENDMENT 1: S9a's published rows.csv has 7,770 rows (v1 read 7,770); the rest of the gate is unchanged.
        self.assertEqual(rt.EXPECTED_ROWS, 7770)
        self.assertEqual(rt.EXPECTED_LATE, 3685)
        self.assertEqual(rt.EXPECTED_LATE_MISSING, 64)
        self.assertEqual(rt.MIN_FETCH, 0.98)
        self.assertEqual(len(rt.EXPECTED_SHA256), 64)


class TestParse(unittest.TestCase):
    def test_parse_ts(self):
        self.assertEqual(rt.parse_ts("2026-06-24T02:00:46.801Z"), datetime.datetime(2026, 6, 24, 2, 0, 46))
        self.assertEqual(rt.parse_ts("2026-06-18T14:28:49Z"), datetime.datetime(2026, 6, 18, 14, 28, 49))
        self.assertEqual(rt.parse_ts("2026-06-18T14:28:49+00:00"), datetime.datetime(2026, 6, 18, 14, 28, 49))
        self.assertEqual(rt.parse_ts("2026-06-18"), datetime.datetime(2026, 6, 18))
        self.assertIsNone(rt.parse_ts(""))
        self.assertIsNone(rt.parse_ts("not a date"))

    def test_norm_ghsa(self):
        self.assertEqual(rt.norm_ghsa("GHSA-JM82-FX9C-MX94"), "GHSA-jm82-fx9c-mx94")

    def test_reduce_record(self):
        obj = {"cveMetadata": {"state": "PUBLISHED", "dateReserved": "2026-05-20T17:44:09.587Z",
                               "datePublished": "2026-09-04T22:11:40.811Z"},
               "containers": {"cna": {"source": {"advisory": "GHSA-fpqx-6722-p65v", "discovery": "UNKNOWN"},
                                      "references": [
                                          {"url": "https://github.com/laravel/framework/security/advisories/"
                                                  "GHSA-5vg9-5847-vvmq"},
                                          {"url": "https://github.com/laravel/framework/pull/60151"},
                                          {"url": "https://github.com/laravel/framework/security/advisories/"
                                                  "GHSA-5vg9-5847-vvmq"}]}}}
        r = rt.reduce_record(obj)
        self.assertEqual(r["state"], "PUBLISHED")
        self.assertEqual(r["source_ghsa"], "GHSA-fpqx-6722-p65v")
        self.assertEqual(r["ref_ghsas"], ["GHSA-5vg9-5847-vvmq"])
        self.assertEqual(r["reserved"], "2026-05-20T17:44:09.587Z")

    def test_reduce_record_bad_source(self):
        r = rt.reduce_record({"cveMetadata": {"state": "PUBLISHED"},
                              "containers": {"cna": {"source": {"advisory": "not-a-ghsa"}}}})
        self.assertEqual(r["source_ghsa"], "")
        self.assertEqual(r["ref_ghsas"], [])


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.rows = rows()
        self.pop = rt.population(self.rows)
        self.out = rt.build(self.pop, RECS)
        self.by = {r["cve"]: r for r in self.out}

    def test_population(self):
        self.assertEqual([r["cve"] for r in self.pop],
                         ["CVE-2026-57204", "CVE-2026-48019", "CVE-2026-48113", "CVE-2025-55300"])

    def test_timing(self):
        self.assertEqual(self.by["CVE-2026-57204"]["timing"], "AFTER")
        self.assertEqual(self.by["CVE-2026-48019"]["timing"], "BEFORE")
        self.assertEqual(self.by["CVE-2026-48113"]["timing"], "BEFORE")
        self.assertEqual(self.by["CVE-2025-55300"]["timing"], "AFTER")

    def test_timing_equal_is_before_and_unknowns(self):
        row = {"adv_reviewed_at": "2026-06-18T14:28:49Z", "adv_published": "2026-06-18T14:28:49Z"}
        self.assertEqual(rt.timing(row, rec("2026-06-18T14:28:49.000Z", "", [])), "BEFORE")
        self.assertEqual(rt.timing(row, rec("2026-06-18T14:28:49Z", "", [], state="REJECTED")), "UNKNOWN")
        self.assertEqual(rt.timing(row, None), "UNKNOWN")
        self.assertEqual(rt.timing(row, rec("", "", [])), "UNKNOWN")
        # reviewed_at empty: falls back to published
        row2 = {"adv_reviewed_at": "", "adv_published": "2026-06-18T14:28:49Z"}
        self.assertEqual(rt.timing(row2, rec("2026-06-19T00:00:00Z", "", [])), "AFTER")

    def test_source_and_modified(self):
        self.assertEqual(self.by["CVE-2026-48019"]["source_matches_ref"], "no")
        self.assertEqual(self.by["CVE-2026-57204"]["source_matches_ref"], "yes")
        self.assertEqual(self.by["CVE-2025-55300"]["modified_after_reserved"], "yes")
        self.assertEqual(self.by["CVE-2026-57204"]["modified_after_reserved"], "no")
        self.assertEqual(rt.source_matches({"ref_ghsa": "GHSA-jm82-fx9c-mx94"}, rec("x", "", [])), "")

    def test_in_window(self):
        self.assertEqual(self.by["CVE-2026-57204"]["in_window"], "yes")
        self.assertEqual(self.by["CVE-2025-55300"]["in_window"], "no")
        self.assertEqual(rt.in_window("2026-07-31T23:59:59Z"), "yes")
        self.assertEqual(rt.in_window("2026-08-01T00:00:00Z"), "no")
        self.assertEqual(rt.in_window(""), "no")

    def test_missing_record_is_fetch_error(self):
        out = rt.build(self.pop, {})
        self.assertTrue(all(r["fetch"] == "FETCH_ERROR" and r["timing"] == "UNKNOWN" for r in out))


class TestGrade(unittest.TestCase):
    def setUp(self):
        self.r = rows()
        self.pop = rt.population(self.r)
        self.out = rt.build(self.pop, RECS)
        self.preds = {p["id"]: p for p in rt.grade(self.out)}

    def test_values(self):
        # listed: 48113 BEFORE, 55300 AFTER -> 1 of 2 BEFORE
        self.assertEqual(self.preds["Q1"]["value"], [1, 2, 50.0])
        self.assertFalse(self.preds["Q1"]["held"])
        # after: 57204 (missing), 55300 (listed) -> 1 of 2 listed
        self.assertEqual(self.preds["Q2"]["value"], [1, 2, 50.0])
        self.assertTrue(self.preds["Q2"]["held"])
        # missing: 57204 AFTER, 48019 BEFORE -> 1 of 2 AFTER
        self.assertEqual(self.preds["Q3"]["value"], [1, 2, 50.0])
        self.assertFalse(self.preds["Q3"]["held"])
        # after in window: 57204 missing (1/1); outside: 55300 listed (0/1)
        self.assertEqual(self.preds["Q4"]["value"], {"in_window": [1, 1, 100.0], "outside": [0, 1, 0.0]})
        self.assertTrue(self.preds["Q4"]["held"])
        self.assertEqual(self.preds["Q5"]["value"], [1, 1, 100.0])
        self.assertTrue(self.preds["Q5"]["held"])
        self.assertEqual(self.preds["Q6"]["value"], [1, 1, 100.0])
        self.assertTrue(self.preds["Q6"]["held"])

    def test_empty_is_not_gradable(self):
        preds = rt.grade([])
        self.assertTrue(all(p["held"] is None for p in preds))

    def test_gate(self):
        ok, checks = rt.gate(self.r, self.pop, self.out, expected_rows=6, expected_late=4, expected_missing=2)
        self.assertTrue(ok, checks)
        ok, checks = rt.gate(self.r, self.pop, self.out)
        self.assertFalse(ok)
        self.assertFalse(checks["rows"])
        self.assertTrue(checks["known"])
        bad = dict(rt.KNOWN, **{"CVE-2026-48113": "AFTER"})
        ok, checks = rt.gate(self.r, self.pop, self.out, expected_rows=6, expected_late=4, expected_missing=2,
                             known=bad)
        self.assertFalse(checks["known"])

    def test_outputs(self):
        d = tempfile.mkdtemp()
        desc = rt.describe(self.out)
        self.assertEqual(desc["timing_by_status"]["AFTER|MISSING"], 1)
        self.assertEqual(desc["after_listed_days_reserved_to_modified"]["n"], 1)
        rt.write_outputs(d, self.out, rt.grade(self.out), desc, True, {"rows": True},
                         {"input": "test", "input_sha256": "0", "run_at": "2026-11-06T00:00:00Z"})
        with open(os.path.join(d, "results.json"), encoding="utf-8") as f:
            res = json.load(f)
        self.assertEqual(len(res["predictions"]), 6)
        with open(os.path.join(d, "rows.csv"), encoding="utf-8") as f:
            self.assertEqual(len(f.read().strip().splitlines()), 5)
        with open(os.path.join(d, "RESULTS-job.md"), encoding="utf-8") as f:
            self.assertIn("| Q6 |", f.read())


if __name__ == "__main__":
    unittest.main()
